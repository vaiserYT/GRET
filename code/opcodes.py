from __future__ import annotations

from enum import IntEnum


class Opcode(IntEnum):
    NOP = 0
    PUSHENV = 1
    POPENV = 2
    PUSH = 3
    PUSHLOC = 4
    PUSHGLB = 5
    PUSHBLTN = 6
    PUSHI = 7
    PUSHF = 8
    PUSHSTR = 9
    DUP = 10
    POP = 11
    POPZ = 12
    CONV = 13
    CALL = 14
    CALLV = 15
    CALLVN = 16
    IF = 17
    GOTO = 18
    SWITCH = 19
    CASE = 20
    BREAK = 21
    CONTINUE = 22
    EXIT = 23
    RET = 24
    NOT = 25
    NEG = 26
    ADD = 27
    SUB = 28
    MUL = 29
    DIV = 30
    MOD = 31
    AND = 32
    OR = 33
    XOR = 34
    SHL = 35
    SHR = 36
    EQ = 37
    NEQ = 38
    LT = 39
    GT = 40
    LTE = 41
    GTE = 42
    ARRAY_PUSH = 43
    ARRAY_POP = 44
    CHKINDEX = 45
    INSTANTIATE = 46
    WITH = 47
    POPEV = 48
    PUSHTAG = 49
    POPTG = 50
    PUSHENVVAR = 51
    PUSHENVREF = 52
    ARRAY_GET = 53
    ARRAY_SET = 54
    ARRAY_PUSH_BACK = 55
    ARRAY_POP_BACK = 56
    ARRAY_GET_REF = 57
    ARRAY_SET_REF = 58
    NEW_OBJECT = 59
    STRUCT_GET = 60
    STRUCT_SET = 61
    IS_INSTANCE_OF = 62
    IS_NULL = 63
    IS_UNDEFINED = 64
    TYPEOF = 65
    CHKNULL = 66
    THROW = 67
    TRY = 68
    CATCH = 69
    ENDTRY = 70
    PUSHLOCREF = 71
    PUSHGLBREF = 72
    PUSHBLTNREF = 73
    ITERATOR = 74
    ITERABLE = 75
    ITER_NEXT = 76
    ITER_END = 77
    PUSH_VARREF = 78
    ARRAY_GET_REF_ID = 79
    ARRAY_SET_REF_ID = 80
    STRUCT_GET_REF = 81
    STRUCT_SET_REF = 82
    STRING_SET = 83
    STRING_GET = 84
    ARRAY_GET_OWNER = 85
    CACHE_TARGET_SELF = 86
    CACHE_TARGET_OTHER = 87
    CACHE_TARGET_GLOBAL = 88
    ASSIGN_REG = 89
    ASSIGN_VAR = 90
    ASSIGN_ARRAY = 91
    ASSIGN_STRUCT = 92
    MULMAT4 = 93
    NEWMAT4 = 94
    PUSHV = 95
    UNKNOWN_96 = 96
    UNKNOWN_97 = 97
    PUSH_LOCAL_ARRAY = 98
    PUSH_GLOBAL_ARRAY = 99
    PUSH_BUILTIN_ARRAY = 100
    REF_TO_INSTANCE = 101
    INSTANCE_TO_REF = 102
    IS_VALID_REF = 103
    PUSH_REF = 104
    POP_REF = 105
    ASSIGN_REF = 106
    ARRAY_GET_REF_B = 107
    UNKNOWN_108 = 108
    UNKNOWN_109 = 109


OPCODE_NAMES: dict[int, str] = {
    v: k for k, v in Opcode.__members__.items()
}


def opcode_name(op: int) -> str:
    return OPCODE_NAMES.get(op, f"UNKNOWN_{op}")


# Variable types for PUSH/POP
class VariableType(IntEnum):
    LOCAL = 0
    GLOBAL = 1
    BUILTIN = 2
    INSTANCE = 3
    SELF = 4
    OTHER = 5
    ARGUMENT = 6


# Conversion types
class ConvType(IntEnum):
    DOUBLE = 0
    FLOAT = 1
    INT32 = 2
    INT64 = 3
    BOOL = 4
    STRING = 5
    ARRAY = 6
    PTR = 7


# Function call kinds (maps to instruction_type field in CALL)
class CallKind(IntEnum):
    NORMAL = 0   # func_id = FUNC entry index
    BUILTIN = 1  # func_id = built-in function hash
    SCRIPT = 2   # func_id = CODE entry index
    METHOD = 3   # func_id = method index
    FUNCTION = 4
    ANONYMOUS = 5
    CONSTRUCTOR = 6


# Jump types for IF
class IfKind(IntEnum):
    IF_EQ = 0
    IF_NEQ = 1
    IF_LT = 2
    IF_GT = 3
    IF_LTE = 4
    IF_GTE = 5
    IF_TRUE = 6
    IF_FALSE = 7
    IF_REF = 8
    IF_UNDEFINED = 9


# Variable access types
class VarAccess(IntEnum):
    READ = 0
    WRITE = 1
    READ_WRITE = 2
    PUSH_ENV = 3
    POP_ENV = 4


VM_HEADER_SIZE = 6


def is_conditional_jump(op: int) -> bool:
    return op in (Opcode.IF,)


def is_unconditional_jump(op: int) -> bool:
    return op in (Opcode.GOTO,)


def is_jump(op: int) -> bool:
    return is_conditional_jump(op) or is_unconditional_jump(op)


def is_call(op: int) -> bool:
    return op in (Opcode.CALL, Opcode.CALLV, Opcode.CALLVN, Opcode.NEW_OBJECT)


def is_push(op: int) -> bool:
    return op in (
        Opcode.PUSH, Opcode.PUSHLOC, Opcode.PUSHGLB, Opcode.PUSHBLTN,
        Opcode.PUSHI, Opcode.PUSHF, Opcode.PUSHSTR, Opcode.PUSHV,
    )


def is_pop(op: int) -> bool:
    return op in (Opcode.POP, Opcode.POPZ, Opcode.POPEV, Opcode.POPTAG)
