# BD Server Bot Testing Checklist

## Pre-Testing Setup

### 1. Add Bangladesh Bot Credentials
In `main.py`, add your BD server bot credentials:

```python
BOT_CREDENTIALS = {
    'india': [
        # ... existing India bots ...
    ],
    'bangladesh': [
        {'uid': 'YOUR_BD_UID', 'password': 'YOUR_BD_PASSWORD'},
        # Add more BD bots as needed
    ]
}
```

### 2. Verify Region Detection
The bot should automatically detect the region from the MajorLogin response.
- India accounts will get region = "IND" or "ind"
- Bangladesh accounts will get region = "BD" or "bd"

## Testing Steps

### Test 1: Bot Connection
- [ ] Start the bot with BD credentials
- [ ] Check console for successful login message
- [ ] Verify bot shows as online in-game
- [ ] Check that region is correctly identified (should print "BD" or "bd")

### Test 2: Basic Commands
Test these commands in private chat or team chat:

#### Join Team Command
- [ ] `/t TEAMCODE` - Bot should join the specified team
- [ ] Verify bot appears in the team lobby

#### Emote Commands
- [ ] `@a EMOTE_ID PLAYER_UID` - Show emote to player in team
- [ ] `/emote_name UID` - Quick emote command (e.g., `/heart 123456789`)
- [ ] `/emote_name TEAMCODE UID` - Auto join, emote, and leave

#### Other Commands
- [ ] `/solo` - Bot leaves current team
- [ ] `/s` - Friend system command
- [ ] `hi` or `help` - Get command list

### Test 3: Squad Invitation
- [ ] Send `/5` command in private chat
- [ ] Bot should send invitation
- [ ] Verify invitation is received

### Test 4: Multi-Bot System (If using Flask API)
- [ ] Test `/api/emote` endpoint with BD bot
- [ ] Verify emote is performed correctly
- [ ] Check bot stays connected after API call

## Expected Behavior

### Correct Packet Headers
The bot should use these packet headers based on region:
- **Bangladesh (BD)**: `0519`
- **India (IND)**: `0514`
- **Other regions**: `0515`

### Functions Using Region-Specific Headers
These functions now support region-specific packets:
1. `GenJoinSquadsPacket` - Joining teams
2. `GenJoinGlobaL` - Global room joins
3. `FS` - Friend system
4. `ExiT` - Leaving squads
5. `Emote_k` - Showing emotes
6. `OpEnSq` - Opening squad
7. `cHSq` - Squad operations
8. `SEnd_InV` - Sending invitations
9. `LagSquad` - Lag squad (if used)
10. `ghost_pakcet` - Ghost packet (if used)

## Troubleshooting

### Bot Not Coming Online
1. **Check region value**: Print the region value after login
   ```python
   print(f"Region detected: {region}")
   ```

2. **Verify packet headers**: Add debug logging to see which packet header is being used
   ```python
   print(f"Using packet header: {packet}")
   ```

3. **Check credentials**: Ensure UID and password are correct for BD server

### Commands Not Working
1. **Verify region parameter**: Ensure all function calls pass the `region` parameter
2. **Check packet format**: Use Wireshark or packet sniffer to verify packet structure
3. **Test with India bot**: If India bot works but BD doesn't, it's a region-specific issue

### Connection Drops
1. **Check TCP connection**: Verify both Online and Chat TCP connections are stable
2. **Monitor console**: Look for error messages or exceptions
3. **Test network**: Ensure stable connection to BD server

## Success Criteria

✅ Bot connects successfully to BD server
✅ Bot appears online in-game
✅ Bot responds to commands
✅ Emotes are displayed correctly
✅ Bot can join/leave teams
✅ No connection drops or errors

## Known Limitations

- Some features may require additional region-specific adjustments
- Packet structures may vary between game versions
- Server-side restrictions may apply

## Support

If you encounter issues:
1. Check the console output for error messages
2. Verify your credentials are correct
3. Ensure you're using the latest game version
4. Check if the server is online and accessible

---
**Last Updated**: 2025
**Compatible With**: Free Fire OB51+
