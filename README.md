flowchart TD
    S([Start]) --> A[sub_7FF727702F84()]
    A --> B[v6 = anti_isDebugPresent()]
    B --> C[result = 0x427DD8E1]

    %% Initial dispatch: IsDebugPresent branch
    C --> D{v6 == 0?\n(!v6)}
    D -- Yes (No Debug) --> E[result = 0xE3FCBDEA]
    D -- No (Debug Detected) --> F[result = 0xA9680CA8]

    %% Common path: Uptime check (anti_GetTickCount_10min) -> may go to long sleep or CPU check
    E --> U1[anti_GetTickCount_10min()]
    F --> U1

    U1 --> U2{anti_GetTickCount_10min() == 0?\n(v1=1)}
    U2 -- Yes (Boot < 10min 등) --> LS1[result = 0xBDC71E76]
    U2 -- No --> CPU1[result = 0x96DA6311]

    %% Long sleep path: 60~120s then go CPU check state
    LS1 --> LS2[Sleep(rand(0xEA60..0x1D4C0))\n(60~120s)]
    LS2 --> CPU1

    %% CPU check state: if CPU<2 -> go to 30~60s sleep state; else go to CHECK state
    CPU1 --> CPU2[sub_7FF7277011A9()\n(CPU Processor < 2 ?)]
    CPU2 --> CPU3{CPU<2 ?\n(sub_7011A9()==0)}
    CPU3 -- Yes --> S30[result = 0xD7107B7A]
    CPU3 -- No --> CHK[result = 0x3C463843]

    %% 30~60s sleep state then back to CHECK state
    S30 --> S30B[Sleep(rand(0x7530..0xEA60))\n(30~60s)]
    S30B --> CHK

    %% Memory check stage (runs when (int)result > 0x3C463842 범위에 해당)
    CHK --> MEM1[sub_7FF727701223()\n(Memory check)]
    MEM1 --> MEM2{Memory 조건 만족?\n(sub_701223()==0)}
    MEM2 -- Yes --> MEMS[result = 0x512BFF6B]
    MEM2 -- No --> TSTATE[result = 0x2ACD709C]

    %% Memory-specific sleep -> tickcount state
    MEMS --> MEMSL[Sleep(rand(0x7530..0xEA60))\n(30~60s)]
    MEMSL --> TSTATE

    %% Tickcount delta anti
    TSTATE --> T1[anti_GetTickcount()]
    T1 --> T2{anti_GetTickcount() == 0?\n(v1=1)}
    T2 -- Yes --> S510[result = 0xD39B4888]
    T2 -- No --> OK[result = 0x1D80F729]

    %% 5~10s sleep then force OK state
    S510 --> S510B[Sleep(rand(0x1388..0x2710))\n(5~10s)]
    S510B --> OK

    %% Terminal: OK returns, otherwise ExitProcess
    OK --> R([Return result=0x1D80F729])

    %% Unhandled/Other states -> Exit
    X[Other/unhandled states\n(예: 0x594E9962/0xA088A9FE/0xFADE51E2/0x4507C434 등)] --> Z([ExitProcess(0)])

    %% Remote debugger present check path (else branch in D39B... range)
    RDP[sub_anti_CheckRemoteDebuggerPresent()] --> RDP2{==0 ?}
    RDP2 -- Yes --> X
    RDP2 -- No --> X
