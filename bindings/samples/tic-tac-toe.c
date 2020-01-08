/*
 * Copyright (C) 2015-2020 "IoT.bzh"
 * Author José Bollo <jose.bollo@iot.bzh>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <json-c/json.h>

#define AFB_BINDING_VERSION 3
#include <afb/afb-binding.h>

static const char SPACE = ' ';
static const char CROSS = 'X';
static const char ROUND = 'O';
static const char NHERE = '+';
static const int DEFLVL = 8;

/*
 * definition of a board
 */
struct board
{
	struct board *next;
	int use_count;
	int moves;
	int history[9];
	int id;
	int level;
	char board[9];
	afb_event_t event;
};

/*
 * list of boards
 */
static struct board *all_boards;

/*
 * Searchs a board having the 'id'.
 * Returns it if found or NULL otherwise.
 */
static struct board *search_board(int id)
{
	struct board *board = all_boards;
	while (board != NULL && board->id != id)
		board = board->next;
	return board;
}

/*
 * Creates a new board and returns it.
 */
static struct board *get_new_board()
{
	/* allocation */
	struct board *board = calloc(1, sizeof *board);

	/* initialisation */
	memset(board->board, SPACE, sizeof board->board);
	board->use_count = 1;
	board->level = DEFLVL;
	board->moves = 0;
	do {
		board->id = (rand() >> 2) % 1000;
	} while(board->id == 0 || search_board(board->id) != NULL);
	board->event = afb_daemon_make_event("board");

	/* link */
	board->next = all_boards;
	all_boards = board;
	return board;
}

/*
 * Release a board
 */
static void release_board(struct board *board)
{
	/* decrease the reference count ... */
	if (--board->use_count == 0) {
		/* ... no more use */
		afb_event_unref(board->event);
		/* unlink from the list of boards */
		struct board **prv = &all_boards;
		while (*prv != NULL && *prv != board)
			prv = &(*prv)->next;
		if (*prv != NULL)
			*prv = board->next;
		/* release the used memory */
		free(board);
	}
}

/*
 * Checks who wins
 * Returns zero if there is no winner
 * Returns the char of the winner if a player won
 */
static char wins(const char b[9], int first, int incr)
{
	char c = b[first];

	return c != SPACE && b[first + incr] == c && b[first + incr + incr] == c ? c : 0;
}

/*
 * Checks who wins
 * Returns zero if there is no winner
 * Returns the char of the winner if a player won
 */
static char winner(const char b[9])
{
	char c;

	c = wins(b, 0, 1);
	if (c)
		return c;

	c = wins(b, 3, 1);
	if (c)
		return c;

	c = wins(b, 6, 1);
	if (c)
		return c;

	c = wins(b, 0, 3);
	if (c)
		return c;

	c = wins(b, 1, 3);
	if (c)
		return c;

	c = wins(b, 2, 3);
	if (c)
		return c;

	c = wins(b, 0, 4);
	if (c)
		return c;

	c = wins(b, 2, 2);
	if (c)
		return c;

	return 0;
}

/* get the color (X or 0) of the move of index 'move' */
static char color(int move)
{
	return (move & 1) == 0 ? CROSS : ROUND;
}

/* adds the move to the board */
static void add_move(struct board *board, int index)
{
	int imove = board->moves++;
	board->history[imove] = index;
	board->board[index] = color(imove);
}

/* get a random possible move index from the board described by 'b' */
static int get_random_move(char b[9])
{
	int index = rand() % 9;
	while (b[index] != SPACE)
		index = (index + 1) % 9;
	return index;
}

/*
 * Scores the position described by 'b'
 * for the player of color 'c' using an analysis of 'depth'.
 * Returns 1 if player 'c' will win.
 * Returns -1 if opponent of player 'c' will win.
 * returns 0 otherwise.
 */
static int score_position(char b[9], char c, int depth)
{
	int i, s, nc, wc, lc;

	/* check if winner */
	if (winner(b) == c)
		return 1;

	/* when depth of analysis is reached return unknown case */
	if (--depth <= 0)
		return 0;

	/* switch to the opponent */
	c = (char)(ROUND + CROSS - c);

	/* inspect opponent moves */
	nc = wc = lc = 0;
	for (i = 0 ; i < 9 ; i++) {
		if (b[i] == SPACE) {
			b[i] = c;
			s = score_position(b, c, depth);
			b[i] = SPACE;
			if (s > 0)
				lc++; /* opponent's victory, inc loose count */
			else if (s < 0)
				wc++; /* current's victory, inc win count */
			else
				nc++; /* none wins, increment null count */
		}
	}
	return lc ? -lc : wc;
}

/* get one move: return the computed index of the move */
static int get_move(struct board *board)
{
	int index, depth, f, s, smax, imax;
	char c;
	char b[9];

	/* compute the depth */
	depth = board->level - 1;
	if (board->moves + depth > 9)
		depth = 9 - board->moves;

	/* case of null depth */
	if (depth == 0)
		return get_random_move(board->board);

	/* depth and more */
	memcpy(b, board->board, 9);
	f = smax = 0;
	c = color(board->moves);
	for (index = 0 ; index < 9 ; index++) {
		if (board->board[index] == SPACE) {
			board->board[index] = c;
			s = score_position(board->board, c, depth);
			board->board[index] = SPACE;
			if (s < 0)
				b[index] = NHERE;
			else if (s <= smax)
				f = 1;
			else {
				smax = s;
				imax = index;
			}
		}
	}
	return smax ? imax : get_random_move(f ? b : board->board);
}

/*
 * get the board description
 */
static struct json_object *describe(struct board *board)
{
	int i;
	char w;
	struct json_object *resu, *arr;

	resu = json_object_new_object();

	json_object_object_add(resu, "boardid", json_object_new_int(board->id));
	json_object_object_add(resu, "level", json_object_new_int(board->level));

	arr = json_object_new_array();
	json_object_object_add(resu, "board", arr);
	for (i = 0 ; i < 9 ; i++)
		json_object_array_add(arr,
				json_object_new_string_len(&board->board[i], 1));

	arr = json_object_new_array();
	json_object_object_add(resu, "history", arr);
	for (i = 0 ; i < board->moves ; i++)
		json_object_array_add(arr, json_object_new_int(board->history[i]));

	w = winner(board->board);
	if (w)
		json_object_object_add(resu, "winner", json_object_new_string_len(&w, 1));
	else if (board->moves == 9)
		json_object_object_add(resu, "winner", json_object_new_string("none"));

	return resu;
}

/*
 * signals a change of the board
 */
static void changed(struct board *board, const char *reason)
{
	afb_event_push(board->event, json_object_new_string(reason));
}

static void *get_new_board_cb(void *closure)
{
	afb_req_t req = closure;
	struct board *board = get_new_board();
	afb_req_subscribe(req, board->event);
	return board;
}

static void release_board_cb(void *closure)
{
	struct board *board = closure;
	return release_board(board);
}

/*
 * retrieves the board of the request
 */
static inline struct board *board_of_req(afb_req_t req)
{
	return afb_req_context(req, 0, get_new_board_cb, release_board_cb, req);
}

/*
 * start a new game
 */
static void new(afb_req_t req)
{
	struct board *board;

	/* retrieves the context for the session */
	board = board_of_req(req);
	AFB_INFO("method 'new' called for boardid %d", board->id);

	/* reset the game */
	memset(board->board, SPACE, sizeof board->board);
	board->moves = 0;

	/* replies */
	afb_req_success(req, NULL, NULL);

	/* signal change */
	changed(board, "new");
}

/*
 * get the board
 */
static void board(afb_req_t req)
{
	struct board *board;
	struct json_object *description;

	/* retrieves the context for the session */
	board = board_of_req(req);
	AFB_INFO("method 'board' called for boardid %d", board->id);

	/* describe the board */
	description = describe(board);

	/* send the board's description */
	afb_req_success(req, description, NULL);
}

/*
 * move a piece
 */
static void move(afb_req_t req)
{
	struct board *board;
	int i;
	const char *index;

	/* retrieves the context for the session */
	board = board_of_req(req);
	AFB_INFO("method 'move' called for boardid %d", board->id);

	/* retrieves the arguments of the move */
	index = afb_req_value(req, "index");
	i = index == NULL ? -1 : atoi(index);

	/* checks validity of arguments */
	if (i < 0 || i > 8) {
		AFB_WARNING("can't move to %s: %s", index?:"?", index?"wrong value":"not set");
		afb_req_fail(req, "error", "bad request");
		return;
	}

	/* checks validity of the state */
	if (winner(board->board) != 0) {
		AFB_WARNING("can't move to %s: game is terminated", index);
		afb_req_fail(req, "error", "game terminated");
		return;
	}

	/* checks validity of the move */
	if (board->board[i] != SPACE) {
		AFB_WARNING("can't move to %s: room occupied", index);
		afb_req_fail(req, "error", "occupied");
		return;
	}

	/* applies the move */
	AFB_INFO("method 'move' for boardid %d, index=%s", board->id, index);
	add_move(board, i);

	/* replies */
	afb_req_success(req, NULL, NULL);

	/* signals change */
	changed(board, "move");
}

/*
 * set the level
 */
static void level(afb_req_t req)
{
	struct board *board;
	int l;
	const char *level;

	/* retrieves the context for the session */
	board = board_of_req(req);
	AFB_INFO("method 'level' called for boardid %d", board->id);

	/* retrieves the arguments */
	level = afb_req_value(req, "level");
	l = level == NULL ? -1 : atoi(level);

	/* check validity of arguments */
	if (l < 1 || l > 10) {
		AFB_WARNING("can't set level to %s: %s", level?:"?", level?"wrong value":"not set");
		afb_req_fail(req, "error", "bad request");
		return;
	}

	/* set the level */
	AFB_INFO("method 'level' for boardid %d, level=%d", board->id, l);
	board->level = l;

	/* replies */
	afb_req_success(req, NULL, NULL);

	/* signals change */
	changed(board, "level");
}

/*
 * Join a board
 */
static void join(afb_req_t req)
{
	struct board *board, *new_board;
	const char *id;

	/* retrieves the context for the session */
	board = board_of_req(req);
	AFB_INFO("method 'join' called for boardid %d", board->id);

	/* retrieves the arguments */
	id = afb_req_value(req, "boardid");
	if (id == NULL)
		goto bad_request;

	/* none is a special id for joining a new session */
	if (strcmp(id, "none") == 0) {
		new_board = get_new_board();
		goto setctx;
	}

	/* searchs the board to join */
	new_board = search_board(atoi(id));
	if (new_board == NULL)
		goto bad_request;

	/*
	 * joining its board is stupid but possible
	 * however when called with the same stored pointer
	 * afb_req_context_set will not call the release
	 * function 'release_board'. So the use_count MUST not
	 * be incremented.
	 */
	if (new_board == board)
		goto success;

	new_board->use_count++;
setctx:
	/* set the new board (and leaves the previous one) */
	afb_req_unsubscribe(req, board->event);
	afb_req_context(req, 1, NULL, release_board_cb, new_board);
	afb_req_subscribe(req, new_board->event);

success:
	/* replies */
	afb_req_success(req, NULL, NULL);
	return;

bad_request:
	AFB_WARNING("can't join boardid %s: %s", id ? : "?", !id ? "no boardid" : atoi(id) ? "not found" : "bad boardid");
	afb_req_fail(req, "error", "bad request");
	return;
}

/*
 * Undo the last move
 */
static void undo(afb_req_t req)
{
	struct board *board;
	int i;

	/* retrieves the context for the session */
	board = board_of_req(req);
	AFB_INFO("method 'undo' called for boardid %d", board->id);

	/* checks the state */
	if (board->moves == 0) {
		AFB_WARNING("can't undo");
		afb_req_fail(req, "error", "bad request");
		return;
	}

	/* undo the last move */
	i = board->history[--board->moves];
	board->board[i] = SPACE;

	/* replies */
	afb_req_success(req, NULL, NULL);

	/* signals change */
	changed(board, "undo");
}

/*
 * computer plays
 */
static void play(afb_req_t req)
{
	struct board *board;
	int index;

	/* retrieves the context for the session */
	board = board_of_req(req);
	AFB_INFO("method 'play' called for boardid %d", board->id);

	/* checks validity of the state */
	if (winner(board->board) != 0 || board->moves == 9) {
		AFB_WARNING("can't play: game terminated (%s)", winner(board->board) ? "has winner" : "no room left");
		afb_req_fail(req, "error", "game terminated");
		return;
	}

	/* gets the move and plays it */
	index = get_move(board);
	add_move(board, index);

	/* replies */
	afb_req_success(req, describe(board), NULL);

	/* signals change */
	changed(board, "play");
}

/*
 * array of the verbs exported to afb-daemon
 */
static const afb_verb_t verbs[] = {
   { .verb="new",   .callback=new },
   { .verb="play",  .callback=play },
   { .verb="move",  .callback=move },
   { .verb="board", .callback=board },
   { .verb="level", .callback=level },
   { .verb="join",  .callback=join },
   { .verb="undo",  .callback=undo },
   { .verb=NULL }
};

/*
 * description of the binding for afb-daemon
 */
const afb_binding_t afbBindingV3 = {
	.api = "tictactoe",
	.specification = NULL,
	.verbs = verbs,
	.noconcurrency = 1
};


