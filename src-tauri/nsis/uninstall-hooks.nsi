; Custom NSIS uninstall hook for Legal AI Assistant
; Prompts user to remove app data (~/.ironclaw/) during uninstall

!macro CUSTOM_UNINSTALL_HOOK
  MessageBox MB_YESNO "Do you also want to remove all application data? This includes the AI model (~3 GB), database, and documents stored in $PROFILE\.ironclaw\.$\n$\nClick Yes to delete everything, or No to keep your data." IDNO SkipDataCleanup
    RMDir /r "$PROFILE\.ironclaw"
  SkipDataCleanup:
!macroend
