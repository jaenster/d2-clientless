# D2GS server→client packet map (1.14d Game.exe)

Ground truth for what the game server sends the client. Recovered from the 1.14d
Game.exe Ghidra project, not from D2MOO (D2MOO only covers `0x00–0x2C` and uses a
different naming scheme). Handler names below are the Ghidra symbol names verbatim.

## Dispatch mechanism

- Stream is opcode-framed (`[opcode][payload…]`), not length-prefixed. Wire size per
  opcode comes from `NET_D2GS_CLIENT_INCOMING_SIZE @0x730AE8` (`0x00–0xB4`); `-1` = the
  size is derived from header fields (see `scPacketSize` in `src/game/packets.zig`).
- `NET_D2GS_CLIENT_PacketHandle_to0xAF @0x0045F7B0` reads the opcode, gets the size via
  `GetIncomingPacketSizeFromTableAndVariableSize @0x0052B920`, then indexes the handler
  table `NET_D2GS_CLIENT_INCOMING @0x007114D0` (175 entries × 12 bytes:
  `{fpHandler, nExpectedSize, fpHandlerUnit}`).
- If `fpHandler` is set it is called directly with a pointer to the packet bytes
  (byte 0 = opcode). If instead `fpHandlerUnit` is set, the dispatcher resolves the
  target unit via `UNITS_FindClientSideUnit @0x00463990` (lookup only — never
  creates) and queues the packet; `SCMD_ProcessIncomingPacketBuffer @0x0045FA40`
  later drains the queue and calls `fpHandlerUnit(pUnit, pBytes)`.
- Shared no-op stub = `0x0045C900`. The compressed container `0xAE` huffman-decodes to
  a run of inner packets that are re-framed by the same size table.

## Unit creation & seed (answers to two key questions)

- Client units are created by the individual assign handlers, not a generic path:
  `0x59 → UNIT_CreatePlayer`, `0x51 → CreateObject`, `0x9C` subcode 0 → item to ground.
  Monster/NPC allocation opcode is not yet confirmed.
- The DRLG/map seed rides in `0x03 LoadAct`: `CLIENT_AllocAct(nAct, nMapSeed, …)`.

## Handler table (opcode → handler → size)

`sz -1` = variable. `STUB` = shared no-op. `ret` = tiny bare-return fn (effective no-op).
`fpU` marks per-unit (queued) handlers.

| op | name | sz | notes |
|-|-|-|-|
| 0x01 | Incoming0x01_GameFlags | 8 | difficulty/expansion/ladder/arena |
| 0x02 | Incoming0x02_LoadSuccess | 1 | client replies JOINGAME 0x6b |
| 0x03 | Incoming0x03_LoadAct | 12 | act + **nMapSeed** + town level + object seed |
| 0x04 | Incoming0x04_LoadComplete | 1 | |
| 0x05 | Incoming0x05_UnloadComplete | 1 | |
| 0x06 | Incoming0x06_GameExit | 1 | |
| 0x07 | Incoming0x07_MapReveal | 6 | x,y,levelId |
| 0x08 | Incoming0x08_MapHide | 6 | x,y,levelId |
| 0x09 | Incoming0x09_AssignLevelWarp | 11 | type,guid,x,y |
| 0x0A | Incoming0x0A_RemoveObject | 6 | type,guid |
| 0x0B | Incoming0x0B_HandShake | 6 | |
| 0x0C | Incoming0x0C_NpcHit | 9 | fpU |
| 0x0D | Incoming0x0D_PlayerStop | 13 | fpU |
| 0x0E | Incoming0x0E_ObjectState | 12 | fpU |
| 0x0F | Incoming0x0F_PlayerMove | 16 | fpU |
| 0x10 | Incoming0x10_CharacterToObject | 16 | fpU |
| 0x11 | Incoming0x11_ReportKill | 8 | |
| 0x15 | Incoming0x15_ReassignPlayer | 11 | type,guid,x,y |
| 0x16 | Incoming0x16 | -1 | batch unit position update |
| 0x17 | Incoming0x17_PlayerBeginCast | -1 | fpU |
| 0x18 | Incoming0x18 | 15 | life/HP (DecodeIncoming0x18 @0x45d900) |
| 0x19..0x1F | Incoming0x19_ItemPageUpdate | 2..6 | gold/exp/page (one handler @0x45d780) |
| 0x20 | Incoming0x20 | 10 | |
| 0x22 | Incoming0x22_SkillQuantity | 12 | |
| 0x23 | Incoming0x23_SelectSkill | 13 | |
| 0x26 | Incoming0x26 | -1 | |
| 0x27 | Incoming0x27_OverheadText | 40 | |
| 0x28 | Incoming0x28_NpcInteract | 103 | |
| 0x51 | Incoming0x51_CreateObject | 14 | CreateObject |
| 0x59 | Incoming0x59 | 26 | UNIT_CreatePlayer |
| 0x5B | Incoming0x5B | -1 | roster player |
| 0x5D | Incoming0x5D | 6 | quest state |
| 0x67 | Incoming0x67_MonsterStop | 16 | fpU |
| 0x68 | Incoming0x68_MonsterBeginCast | 21 | fpU |
| 0x69 | Incoming0x69_MonsterSpell | 12 | fpU |
| 0x6A | RecvNpcStateToEntity | 12 | fpU |
| 0x6B | Incoming0x6B_MonsterBeginCastWalk | 16 | fpU |
| 0x6C | Incoming0x6C_MonsterCastStationary | 16 | fpU |
| 0x73 | Incoming0x73_WaypointInit | 32 | |
| 0x77 | Incoming0x77 | 2 | trade window |
| 0x7B | Incoming0x7B_SetSkillSlot | 8 | |
| 0x7C | Incoming0x7C_ItemAction | 6 | |
| 0x95 | Incoming0x95_PlayerJoin | 13 | HP/mana/stamina + reposition local player |
| 0x96 | Incoming0x96_PlayerLeave | 9 | |
| 0x9C | Incoming0x9C | -1 | item ground/inventory/belt (sub-op byte) |
| 0x9D | Incoming0x9D | -1 | |
| 0x9E..0xA2 | Incoming0x9Eto0xA2 | 7,8,10,7,8 | monster stat set/add (one handler @0x45d540) |
| 0xA7 | Incoming0xA7 | 7 | state |
| 0xA8 | Incoming0xA8 | -1 | state + statlist |
| 0xA9 | Incoming0xA9 | 7 | state |
| 0xAA | Incoming0xAA | -1 | state + stat |
| 0xAC | Incoming0xAC | -1 | state |
| 0xAE | Incoming0xAE | -1 | compressed container (huffman) |

Opcodes not listed are either `STUB`, bare-`ret` no-ops (`0x12–0x14`, `0x45`, `0x54`,
`0x66`, `0x6E–0x72`), or not-yet-named generic `Incoming0xNN` handlers. See
`src/game/packets.zig` for the full per-opcode table the code drives off.
