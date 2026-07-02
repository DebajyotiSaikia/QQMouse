add_executable(skittermouse_tests
    test_main.cpp
    event_types_tests.cpp
    ownership_state_tests.cpp
    server_election_tests.cpp
    config_tests.cpp
    key_translation_tests.cpp
    wake_flow_tests.cpp
    crypto_tests.cpp
    pairing_tests.cpp
    pairing_exchange_tests.cpp
    session_token_tests.cpp
    net_tests.cpp
    transport_tests.cpp
    encrypted_transport_tests.cpp
    input_logic_tests.cpp
    app_logic_tests.cpp
    connection_manager_tests.cpp
    connection_service_tests.cpp
    secure_link_tests.cpp
    feature_tests.cpp
    file_session_tests.cpp
    file_channel_tests.cpp
    e2e_mesh_tests.cpp
    e2e_flow_tests.cpp
    e2e_meshnode_tests.cpp
    e2e_encrypted_mesh_tests.cpp
    e2e_secure_connection_tests.cpp
    e2e_full_system_tests.cpp
    filepromise_win_tests.cpp
    file_promise_announce_tests.cpp
)
target_link_libraries(skittermouse_tests PRIVATE skittermouse_platform)

add_test(NAME skittermouse_tests COMMAND skittermouse_tests)
