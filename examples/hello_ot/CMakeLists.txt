add_application(HelloOT
    hello_ot.c
    hello_ot.r
)

# Link against our OT transport source (not a library yet — just compile it in)
target_sources(HelloOT PRIVATE
    ${CMAKE_SOURCE_DIR}/src/ot_transport.c
)

target_include_directories(HelloOT PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)
