add_application(Postman
    postman.c
    postman.r
    http.c
    ui.c
    ../common/seed_file.c
)

target_link_libraries(Postman certainly)
target_include_directories(Postman PRIVATE ../common)
