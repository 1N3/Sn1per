AUTHOR='@xer0dayz'
VULN_NAME='Drupal Detected'
FILENAME="$LOOT_DIR/web/headers-htt*-$TARGET.txt"
MATCH="X\-Generator\:\ Drupal\ "
SEVERITY='P5 - INFO'
GREP_OPTIONS='-i'
SEARCH='positive'
SECONDARY_COMMANDS=''