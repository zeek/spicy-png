spicy_add_analyzer(
    NAME File
    PACKAGE_NAME File
    SOURCES analyzer.spicy analyzer.evt zeek_analyzer.spicy
    SCRIPTS __load__.zeek main.zeek)
