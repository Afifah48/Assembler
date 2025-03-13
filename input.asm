MOV R1, R2
    ADD R3, R1, R2
    SUB R4, R3, R1
    B LOOP

LOOP: MUL R5, R1, R2
    CMP R2, R3
    BEQ  END
    NOT R6, R1
    LSL R7, R1, 3
    LD R2, 10
    ST R3, 20
    CALL FUNCTION
    RET

FUNCTION: OR R1, R2, R3
    MOD R5, R3, R4
    RET

END: HLT