add_application(HelloOT
    hello_ot.c
    hello_ot.r
)

target_include_directories(HelloOT PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(HelloOT certainly)
