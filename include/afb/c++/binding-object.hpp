#pragma once

/*
 * Copyright (C) 2018 "IoT.bzh"
 * Author Loïc Collignon <loic.collignon@iot.bzh>
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

#include "../afb-binding.h"
#include <cassert>
#include <string>

namespace afb
{
	/**
	 * @brief Create a new API.
	 * @tparam TApi The Api's concrete class to create an instance from.
	 * @param[in] handle Parent API.
	 * @param[in] name API's name.
	 * @param[in] info API's description.
	 * @param[in] noconcurrency Zero for a reentrant API, non-zero otherwise.
	 * @return The created API.
	 */
	template <typename TApi>
	TApi* new_api(afb_api_t handle, const std::string& name, const std::string& info = "", int noconcurrency = 1)
	{
		TApi* api = new TApi();
		afb_api_new_api(
			handle,
			name.c_str(),
			info == "" ? nullptr : info.c_str(),
			noconcurrency,
			TApi::Traits::preinit,
			api
		);
		return api;
	}

	/**
	 * @brief Default Api's traits implementation.
	 * @tparam TApi The Api's concrete class.
	 */
	template <typename TApi>
	struct ApiTraits
	{
		/**
		 * @brief TApi's method pointer.
		 */
		using TVerbCallback = void(TApi::*)(req);

		/***
		 * @brief TApi's const method pointer.
		 */
		using TVerbCallbackConst = void(TApi::*)(req) const;

		/**
		 * @brief Pre-init callback for an api created using @c afb::api::new_api.
		 * @param[in] closure Pointer to the API object.
		 * @param[in] handle Handle of the API.
		 * @return Zero on success, non-zero otherwise.
		 */
		static int preinit(void* closure, afb_api_t handle)
		{
			assert(closure != nullptr);
			assert(handle != nullptr);

			afb_api_set_userdata(handle, closure);

			TApi* api = reinterpret_cast<TApi*>(closure);

			if (afb_api_on_init(handle, TApi::Traits::init))
			{
				AFB_API_ERROR(handle, "Failed to register init handler callback.");
				return -1;
			}

			if (afb_api_on_event(handle, TApi::Traits::event))
			{
				AFB_API_ERROR(handle, "Failed to register event handler callback.");
				return -2;
			}

			api->handle_ = handle;
			return api->preinit(handle);
		}

		/**
		 * @brief Init callback for an api created using @c afb::api::new_api.
		 * @param[in] handle Handle to the API to initialize.
		 * @return Zero on success, non-zero otherwise.
		 */
		static int init(afb_api_t handle)
		{
			assert(handle != nullptr);

			void* userdata = afb_api_get_userdata(handle);
			assert(userdata != nullptr);

			TApi* api = reinterpret_cast<TApi*>(userdata);
			return api->init();
		}

		/**
		 * @brief Event callback for an api created using @c afb::api::new_api.
		 * @param[in] handle Handle to the API that is receiving an event.
		 * @param[in] event The event's name.
		 * @param[in] object The event's json argument.
		 */
		static void event(afb_api_t handle, const char* event, json_object* object)
		{
			assert(handle != nullptr);

			void* userdata = afb_api_get_userdata(handle);
			assert(userdata != nullptr);

			TApi* api = reinterpret_cast<TApi*>(userdata);
			api->event(event, object);
		}

		/**
		 * @brief Verb callback for a verb added using @c afb::api::add_verb.
		 * @tparam callback TApi's method to call
		 * @param[in] r Request to handle.
		 */
		template <TVerbCallback callback>
		static void verb(afb_req_t r)
		{
			assert(r != nullptr);

			afb_api_t handle = afb_req_get_api(r);
			if (handle)
			{
				void* userdata = afb_api_get_userdata(handle);
				if (userdata)
				{
					TApi* api = reinterpret_cast<TApi*>(userdata);
					(api->*callback)(afb::req(r));
				}
				else
				{
					afb_req_fail(r, "Failed to get the API object!", nullptr);
				}
			}
			else
			{
				afb_req_fail(r, "Failed to get the corresponding API from the query!", nullptr);
			}
		}

		/**
		 * @brief Verb callback for a verb added using @c afb::api::add_verb.
		 * @tparam callback TApi's const method to call.
		 * @param[in] req Request to handle.
		 */
		template <TVerbCallbackConst callback>
		static void verb(afb_req_t r)
		{
			assert(r != nullptr);

			afb_api_t handle = afb_req_get_api(r);
			if (handle)
			{
				void* userdata = afb_api_get_userdata(handle);
				if (userdata)
				{
					TApi* api = reinterpret_cast<TApi*>(userdata);
					(api->*callback)(afb::req(r));
				}
				else
				{
					afb_req_fail(r, "Failed to get the API object!", nullptr);
				}
			}
			else
			{
				afb_req_fail(r, "Failed to get the corresponding API from the query!", nullptr);
			}
		}
	};

	/**
	 * @brief Base class for API implementation.
	 * @tparam TApi The Api's concrete class.
	 * @tparam TTraits The Api's static callback implementation.
	 */
	template <
		typename TApi,
		typename TTraits = ApiTraits<TApi>
	>
	class base_api_t
	{
		friend TTraits;

	public:
		using Traits = TTraits;

	private:
		// Non-copyable
		base_api_t(const base_api_t&) = delete;
		base_api_t& operator=(const base_api_t&) = delete;

	protected:
		afb_api_t handle_;

		/**
		 * @brief Default constructor.
		 */
		explicit base_api_t() = default;

		/**
		 * @brief Move constructor.
		 */
		explicit base_api_t(base_api_t&&) = default;

		/**
		 * @brief Add a verb to an API.
		 * @param[in] api API on which the verb should be added.
		 * @param[in] verb Verb's name.
		 * @param[in] info Verb's description.
		 * @param[in] auth Verb's permissions required.
		 * @param[in] session Verb's session handling.
		 * @param[in] glob is the verb glob name.
		 * @return Zero if success, non-zero otherwise.
		 */
		template <typename TTraits::TVerbCallback Callback>
		int add_verb(const std::string& verb, const std::string& info, void* vcbdata = nullptr, const struct afb_auth* auth = nullptr, uint32_t session = AFB_SESSION_NONE_X2, int glob = 0)
		{
			return afb_api_add_verb(
				handle_,
				verb.c_str(),
				info == "" ? nullptr : info.c_str(),
				TTraits::template verb<Callback>,
				vcbdata,
				auth,
				session,
				glob
			);
		}

		/**
		 * @brief Add a verb to an API.
		 * @param[in] api API on which the verb should be added.
		 * @param[in] verb Verb's name.
		 * @param[in] info Verb's description.
		 * @param[in] auth Verb's permissions required.
		 * @param[in] session Verb's session handling.
		 * @param[in] glob is the verb glob name.
		 * @return Zero if success, non-zero otherwise.
		 */
		template <typename TTraits::TVerbCallbackConst Callback>
		int add_verb(const std::string& verb, const std::string& info, void* vcbdata = nullptr, const struct afb_auth* auth = nullptr, uint32_t session = AFB_SESSION_NONE_X2, int glob = 0)
		{
			return afb_api_add_verb(
				handle_,
				verb.c_str(),
				info == "" ? nullptr : info.c_str(),
				TTraits::template verb<Callback>,
				vcbdata,
				auth,
				session,
				glob
			);
		}

	public:
		/**
		 * @brief Move assignation operator.
		 */
		base_api_t& operator=(base_api_t&&) = default;

		/**
		 * @brief Get the API's handle.
		 * @return The API's handle.
		 */
		afb_api_t handle() const { return handle_; }

		/**
		 * @brief Implicit conversion to C handle.
		 * @return The API's handle.
		 */
		operator afb_api_t() const { return handle_; }

		/**
		 * @brief Destructor.
		 */
		virtual ~base_api_t()
		{
			if (handle_ && afb_api_delete_api(handle_))
				AFB_API_ERROR(handle_, "Failed to delete API.");
		}

		/**
		 * @brief Called by the binder during the API's pre-init phase.
		 * @param[in] handle Handle representing the API on the binder's side.
		 * @return Zero if success, non-zero otherwise.
		 */
		virtual int preinit(afb_api_t handle) { return 0; }

		/**
		 * @brief Called by the binder during the API's init phase.
		 * @return Zero on success, non-zero otherwise.
		 */
		virtual int init() { return 0; }

		/**
		 * @brief Called by the binder when an event is received for this API.
		 * @param[in] name Event's name.
		 * @param[in] arg Event's argument.
		 */
		virtual void event(const std::string& name, json_object* arg) { }
	};
}
