# Appendix G — AgentDojo v1.2.2 registry mapping

Generated from `src/firewall/registry/agentdojo_<suite>.yaml` (pinned commit in `bench.lock`); policies: `src/firewall/policies/agentdojo/ad_<suite>.yaml`. Coverage is complete for all four suites (`registry_map.coverage`). Deviations from our own registry: Slack users/channels/URLs and banking recipients are `text` (AgentDojo uses bare names, scheme-less URLs and pays named merchants); `get_channels` output is untrusted (an injection vector lives in an external channel name); times are free-form `text` meta.

## banking

| tool | side effect | sink destination | args (type/role) | output trust |
|---|---|---|---|---|
| `get_balance` | read | – | – | own_record |
| `get_iban` | read | – | – | own_record |
| `get_most_recent_transactions` | read | – | n:int/meta | untrusted |
| `get_scheduled_transactions` | read | – | – | untrusted |
| `get_user_info` | read | – | – | own_record |
| `read_file` | read | – | file_path:path/selector | untrusted |
| `schedule_transaction` | payment | text via ['recipient'] | recipient:text/authority, amount:amount/bounded, subject:text/content, date:text/meta, recurring:bool/meta | own_record |
| `send_money` | payment | text via ['recipient'] | recipient:text/authority, amount:amount/bounded, subject:text/content, date:text/meta | own_record |
| `update_password` | auth | – | password:secret_text/authority | own_record |
| `update_scheduled_transaction` | payment | text via ['recipient'] | id:int/selector, recipient:text/authority, amount:amount/bounded, subject:text/content, date:text/meta, recurring:bool/meta | own_record |
| `update_user_info` | write | – | first_name:text/content, last_name:text/content, street:text/content, city:text/content | own_record |

## slack

| tool | side effect | sink destination | args (type/role) | output trust |
|---|---|---|---|---|
| `add_user_to_channel` | share | text via ['user'] | user:text/authority, channel:text/selector | own_record |
| `get_channels` | read | – | – | untrusted |
| `get_users_in_channel` | read | – | channel:text/selector | own_record |
| `get_webpage` | fetch | – | url:text/authority | untrusted |
| `invite_user_to_slack` | share | email via ['user_email'] | user:text/authority, user_email:email/authority | own_record |
| `post_webpage` | external_comm | text via ['url'] | url:text/authority, content:text/content | own_record |
| `read_channel_messages` | read | – | channel:text/selector | untrusted |
| `read_inbox` | read | – | user:text/selector | untrusted |
| `remove_user_from_slack` | delete | – | user:text/authority | own_record |
| `send_channel_message` | external_comm | text via ['channel'] | channel:text/authority, body:text/content | own_record |
| `send_direct_message` | external_comm | text via ['recipient'] | recipient:text/authority, body:text/content | own_record |

## travel

| tool | side effect | sink destination | args (type/role) | output trust |
|---|---|---|---|---|
| `cancel_calendar_event` | delete | – | event_id:id/selector | own_record |
| `check_restaurant_opening_hours` | read | – | restaurant_names:list/meta | untrusted |
| `create_calendar_event` | write | email via ['participants'] | title:text/content, start_time:text/meta, end_time:text/meta, description:text/content, participants:list/authority, location:text/content | own_record |
| `get_all_car_rental_companies_in_city` | read | – | city:text/meta | untrusted |
| `get_all_hotels_in_city` | read | – | city:text/meta | untrusted |
| `get_all_restaurants_in_city` | read | – | city:text/meta | untrusted |
| `get_car_fuel_options` | read | – | company_name:list/meta | untrusted |
| `get_car_price_per_day` | read | – | company_name:list/meta | untrusted |
| `get_car_rental_address` | read | – | company_name:list/meta | untrusted |
| `get_car_types_available` | read | – | company_name:list/meta | untrusted |
| `get_contact_information_for_restaurants` | read | – | restaurant_names:list/meta | untrusted |
| `get_cuisine_type_for_restaurants` | read | – | restaurant_names:list/meta | untrusted |
| `get_day_calendar_events` | read | – | day:text/meta | untrusted |
| `get_dietary_restrictions_for_all_restaurants` | read | – | restaurant_names:list/meta | untrusted |
| `get_flight_information` | read | – | departure_city:text/meta, arrival_city:text/meta | untrusted |
| `get_hotels_address` | read | – | hotel_name:text/meta | untrusted |
| `get_hotels_prices` | read | – | hotel_names:list/meta | untrusted |
| `get_price_for_restaurants` | read | – | restaurant_names:list/meta | untrusted |
| `get_rating_reviews_for_car_rental` | read | – | company_name:list/meta | untrusted |
| `get_rating_reviews_for_hotels` | read | – | hotel_names:list/meta | untrusted |
| `get_rating_reviews_for_restaurants` | read | – | restaurant_names:list/meta | untrusted |
| `get_restaurants_address` | read | – | restaurant_names:list/meta | untrusted |
| `get_user_information` | read | – | – | own_record |
| `reserve_car_rental` | payment | – | company:text/authority, start_time:text/meta, end_time:text/meta | own_record |
| `reserve_hotel` | payment | – | hotel:text/authority, start_day:text/meta, end_day:text/meta | own_record |
| `reserve_restaurant` | payment | – | restaurant:text/authority, start_time:text/meta | own_record |
| `search_calendar_events` | read | – | query:text/meta, date:text/meta | untrusted |
| `send_email` | external_comm | email via ['recipients', 'cc', 'bcc'] | recipients:list/authority, subject:text/content, body:text/content, attachments:list/content, cc:list/authority, bcc:list/authority | own_record |

## workspace

| tool | side effect | sink destination | args (type/role) | output trust |
|---|---|---|---|---|
| `add_calendar_event_participants` | share | email via ['participants'] | event_id:id/selector, participants:list/authority | own_record |
| `append_to_file` | write | – | file_id:id/selector, content:text/content | untrusted |
| `cancel_calendar_event` | delete | – | event_id:id/selector | own_record |
| `create_calendar_event` | write | email via ['participants'] | title:text/content, start_time:text/meta, end_time:text/meta, description:text/content, participants:list/authority, location:text/content | own_record |
| `create_file` | write | – | filename:text/authority, content:text/content | own_record |
| `delete_email` | delete | – | email_id:id/selector | own_record |
| `delete_file` | delete | – | file_id:id/selector | own_record |
| `get_current_day` | read | – | – | trusted |
| `get_day_calendar_events` | read | – | day:text/meta | untrusted |
| `get_draft_emails` | read | – | – | untrusted |
| `get_file_by_id` | read | – | file_id:id/selector | untrusted |
| `get_received_emails` | read | – | – | untrusted |
| `get_sent_emails` | read | – | – | untrusted |
| `get_unread_emails` | read | – | – | untrusted |
| `list_files` | read | – | – | untrusted |
| `reschedule_calendar_event` | write | – | event_id:id/selector, new_start_time:text/meta, new_end_time:text/meta | own_record |
| `search_calendar_events` | read | – | query:text/meta, date:text/meta | untrusted |
| `search_contacts_by_email` | read | – | query:text/meta | own_record |
| `search_contacts_by_name` | read | – | query:text/meta | own_record |
| `search_emails` | read | – | query:text/meta, sender:email/meta | untrusted |
| `search_files` | read | – | query:text/meta | untrusted |
| `search_files_by_filename` | read | – | filename:text/meta | untrusted |
| `send_email` | external_comm | email via ['recipients', 'cc', 'bcc'] | recipients:list/authority, subject:text/content, body:text/content, attachments:list/content, cc:list/authority, bcc:list/authority | own_record |
| `share_file` | share | email via ['email'] | file_id:id/selector, email:email/authority, permission:text/meta | own_record |
