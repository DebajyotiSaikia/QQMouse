#include "test_framework.h"

void run_event_types_tests();
void run_ownership_state_tests();
void run_server_election_tests();
void run_config_tests();
void run_key_translation_tests();
void run_wake_flow_tests();
void run_crypto_tests();
void run_pairing_tests();
void run_pairing_exchange_tests();
void run_session_token_tests();
void run_net_tests();
void run_transport_tests();
void run_encrypted_transport_tests();
void run_input_logic_tests();
void run_app_logic_tests();
void run_connection_manager_tests();
void run_connection_service_tests();
void run_secure_link_tests();
void run_feature_tests();
void run_file_session_tests();
void run_file_channel_tests();
void run_e2e_mesh_tests();
void run_e2e_flow_tests();
void run_e2e_meshnode_tests();
void run_e2e_encrypted_mesh_tests();
void run_e2e_secure_connection_tests();
void run_e2e_full_system_tests();
void run_filepromise_win_tests();
void run_file_promise_announce_tests();

int main() {
    run_event_types_tests();
    run_ownership_state_tests();
    run_server_election_tests();
    run_config_tests();
    run_key_translation_tests();
    run_wake_flow_tests();
    run_crypto_tests();
    run_pairing_tests();
    run_pairing_exchange_tests();
    run_session_token_tests();
    run_net_tests();
    run_transport_tests();
    run_encrypted_transport_tests();
    run_input_logic_tests();
    run_app_logic_tests();
    run_connection_manager_tests();
    run_connection_service_tests();
    run_secure_link_tests();
    run_feature_tests();
    run_file_session_tests();
    run_file_channel_tests();
    run_e2e_mesh_tests();
    run_e2e_flow_tests();
    run_e2e_meshnode_tests();
    run_e2e_encrypted_mesh_tests();
    run_e2e_secure_connection_tests();
    run_e2e_full_system_tests();
    run_filepromise_win_tests();
    run_file_promise_announce_tests();

    std::printf("\n%d checks, %d failure(s)\n", smtest::g_checks, smtest::g_failures);
    return smtest::g_failures == 0 ? 0 : 1;
}
