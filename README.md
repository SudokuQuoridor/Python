flowchart TD
    S([Start]) --> A["sub_7FF727702F84()"];
    A --> B["v6 = anti_isDebugPresent()"];
    B --> C["result = 0x427DD8E1"];

    C --> D{"v6 == 0? (!v6)"};
    D -- "Yes (No Debug)" --> E["result = 0xE3FCBDEA"];
    D -- "No (Debug Detected)" --> F["result = 0xA9680CA8"];

    E --> U1["anti_GetTickCount_10min()"];
    F --> U1;

    U1 --> U2{"anti_GetTickCount_10min() == 0? (v1=1)"};
    U2 -- "Yes (Boot less than 10min 등)" --> LS1["result = 0xBDC71E76"];
    U2 -- "No" --> CPU1["result = 0x96DA6311"];

    LS1 --> LS2["Sleep(rand(0xEA60..0x1D4C0)) (60~120s)"];
    LS2 --> CPU1;

    CPU1 --> CPU2["sub_7FF7277011A9() (CPU Processor count check)"];
    CPU2 --> CPU3{"CPU less than 2? (sub_7011A9()==0)"};
    CPU3 -- "Yes" --> S30["result = 0xD7107B7A"];
    CPU3 -- "No" --> CHK["result = 0x3C463843"];

    S30 --> S30B["Sleep(rand(0x7530..0xEA60)) (30~60s)"];
    S30B --> CHK;

    CHK --> MEM1["sub_7FF727701223() (Memory check)"];
    MEM1 --> MEM2{"Memory condition OK? (sub_701223()==0)"};
    MEM2 -- "Yes" --> MEMS["result = 0x512BFF6B"];
    MEM2 -- "No" --> TSTATE["result = 0x2ACD709C"];

    MEMS --> MEMSL["Sleep(rand(0x7530..0xEA60)) (30~60s)"];
    MEMSL --> TSTATE;

    TSTATE --> T1["anti_GetTickcount()"];
    T1 --> T2{"anti_GetTickcount() == 0? (v1=1)"};
    T2 -- "Yes" --> S510["result = 0xD39B4888"];
    T2 -- "No" --> OK["result = 0x1D80F729"];

    S510 --> S510B["Sleep(rand(0x1388..0x2710)) (5~10s)"];
    S510B --> OK;

    OK --> R(["Return result = 0x1D80F729"]);

    X["Other/unhandled states (e.g., 0x594E9962 / 0xA088A9FE / 0xFADE51E2 / 0x4507C434)"] --> Z(["ExitProcess(0)"]);

    RDP["sub_anti_CheckRemoteDebuggerPresent()"] --> RDP2{"== 0 ?"};
    RDP2 -- "Yes" --> X;
    RDP2 -- "No" --> X;
