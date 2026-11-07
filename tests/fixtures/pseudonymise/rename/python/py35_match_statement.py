def route(command_name):
    match command_name:
        case "pay":
            return 1
        case _:
            return 0
