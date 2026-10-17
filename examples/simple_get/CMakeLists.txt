add_application(SimpleGet
    simple_get.c
    simple_get.r
    ../common/seed_file.c
)

target_link_libraries(SimpleGet certainly)
target_include_directories(SimpleGet PRIVATE ../common)
