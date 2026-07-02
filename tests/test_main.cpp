#include "test_framework.h"

void run_event_types_tests();
void run_ownership_state_tests();
void run_server_election_tests();
void run_config_tests();
void run_key_translation_tests();
void run_crypto_tests();
void run_pairing_tests();
void run_session_token_tests();
void run_net_tests();
void run_input_logic_tests();
void run_app_logic_tests();
void run_e2e_mesh_tests();
void run_e2e_flow_tests();

int main() {
    run_event_types_tests();
    run_ownership_state_tests();
    run_server_election_tests();
    run_config_tests();
    run_key_translation_tests();
    run_crypto_tests();
    run_pairing_tests();
    run_session_token_tests();
    run_net_tests();
    run_input_logic_tests();
    run_app_logic_tests();
    run_e2e_mesh_tests();
    run_e2e_flow_tests();

    std::printf("\n%d checks, %d failure(s)\n", smtest::g_checks, smtest::g_failures);
    return smtest::g_failures == 0 ? 0 : 1;
}
