from enum import Enum, auto

class CommandEnum(Enum):
    STATION_MOVE = 'STATION_MOVE'
    LU_LOAD = "LU_LOAD"
    LU_UNLOAD = "LU_UNLOAD"
    LU_LOADUNLOAD = "LU_LOADUNLOAD"