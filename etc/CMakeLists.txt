file(GLOB lua_scripts "*.lua")
install(FILES ${lua_scripts} DESTINATION /etc/sems/scripts)
