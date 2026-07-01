add_executable(skittermouse_tests
    test_main.cpp
    event_types_tests.cpp
    ownership_state_tests.cpp
    server_election_tests.cpp
    config_tests.cpp
    key_translation_tests.cpp
    crypto_tests.cpp
    pairing_tests.cpp
    session_token_tests.cpp
    net_tests.cpp
    input_logic_tests.cpp
    e2e_mesh_tests.cpp
)
target_link_libraries(skittermouse_tests PRIVATE skittermouse_platform)

add_test(NAME skittermouse_tests COMMAND skittermouse_tests)
