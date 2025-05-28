      mkdir -p $LOOT_DIR/web/javascript/$TARGET 2> /dev/null
      cd $LOOT_DIR/web/javascript/$TARGET
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED DOWNLOADING ALL JAVASCRIPT FILES $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      egrep --binary-files=text "\.js" $LOOT_DIR/web/spider-$TARGET.txt 2> /dev/null | egrep -v '.json|.jsp'
      for a in `egrep --binary-files=text "\.js" $LOOT_DIR/web/spider-$TARGET.txt 2> /dev/null | egrep -v '.json|.jsp' | head -n $MAX_JAVASCRIPT_FILES | cut -d\? -f1 | sort -u`; do echo "Downloading - $a" && FILENAME=$(echo "$a" | awk -F/ '{print $(NF-0)}') && curl --connect-timeout 10 --max-time 10 -s -R -L --insecure $a | js-beautify - > $FILENAME 2> /dev/null; done;
      for a in `egrep --binary-files=text "\.js" $LOOT_DIR/web/weblinks-htt*-$TARGET.txt 2> /dev/null | egrep -v '.json|.jsp' | egrep -i 'http' | head -n $MAX_JAVASCRIPT_FILES | cut -d\? -f1 | sort -u`; do echo "Downloading - $a" && FILENAME=$(echo "$a" | awk -F/ '{print $(NF-0)}') && curl --connect-timeout 10 --max-time 10 -s -R -L --insecure $a | js-beautify - > $FILENAME 2> /dev/null; done;
      for a in `egrep --binary-files=text "\.js" $LOOT_DIR/web/weblinks-htt*-$TARGET.txt 2> /dev/null | egrep -v '.json|.jsp' | egrep -iv 'http' | head -n $MAX_JAVASCRIPT_FILES | cut -d\? -f1 | sort -u`; do echo "Downloading - https://$a" && FILENAME=$(echo "https://$a" | awk -F/ '{print $(NF-0)}') && curl --connect-timeout 10 --max-time 10 -s -R -L --insecure $a | js-beautify - > $FILENAME 2> /dev/null; done;
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED DISPLAYING ALL JAVASCRIPT COMMENTS $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      cat $LOOT_DIR/web/javascript/$TARGET/*.js 2> /dev/null | egrep "\/\/|\/\*" | sort -u | tee $LOOT_DIR/web/javascript-$TARGET-comments.txt 
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED DISPLAYING ALL JAVASCRIPT LINKS $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      cat $LOOT_DIR/web/javascript/$TARGET/*.js 2> /dev/null | grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*" | sort -u | tee $LOOT_DIR/web/javascript-$TARGET-urls.txt
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING RETIRE.JS $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      if ! command -v retire &> /dev/null; then
        echo -e "${OKRED}Retire.js not found. Installing...${RESET}"
        npm install -g retire
      fi
      if command -v retire &> /dev/null; then
        for file in $LOOT_DIR/web/javascript/$TARGET/*.js; do
          echo "Analyzing $file with Retire.js"
          retire --js --outputformat text --outputpath $LOOT_DIR/web/javascript-$TARGET-retire.txt --path $LOOT_DIR/web/javascript/$TARGET/
        done
        echo "Retire.js analysis complete. Results saved to $LOOT_DIR/web/javascript-$TARGET-retire.txt"
      else
        echo -e "${OKRED}Failed to install Retire.js. Skipping Retire.js analysis.${RESET}"
      fi
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING LINKFINDER $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      cd $PLUGINS_DIR/LinkFinder/
      for a in `ls $LOOT_DIR/web/javascript/$TARGET/*.js 2> /dev/null`; do echo "Analyzing - $a" && FILENAME=$(echo "$a" | awk -F/ '{print $(NF-0)}') && python3 linkfinder.py -d -i $a -o cli 2> /dev/null | egrep -v "application\/|SSL error" > $LOOT_DIR/web/javascript-linkfinder-$TARGET-$FILENAME.txt 2> /dev/null; done;
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED DISPLAYING PATH RELATIVE LINKS $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      cat $LOOT_DIR/web/javascript-linkfinder-$TARGET-*.txt 2> /dev/null | grep -v "Running " | awk '{print $1}' | sort -u | tee $LOOT_DIR/web/javascript-$TARGET-path-relative.txt
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED DISPLAYING JAVASCRIPT URLS $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      grep -h http $LOOT_DIR/web/javascript-linkfinder-$TARGET-*.txt 2> /dev/null | grep -v "Running " | awk '{print $1}' | egrep "http\:\/\/|https\:\/\/" | sort -u | tee $LOOT_DIR/web/javascript-$TARGET-linkfinder-urls.txt
      sort -u $LOOT_DIR/web/javascript-$TARGET-urls.txt $LOOT_DIR/web/javascript-$TARGET-linkfinder-urls.txt 2> /dev/null > $LOOT_DIR/web/javascript-$TARGET-urls-sorted.txt
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED DISPLAYING JAVASCRIPT DOMAINS $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      grep -h http $LOOT_DIR/web/javascript-linkfinder-$TARGET-*.txt 2> /dev/null | grep -v "Running " | awk '{print $1}' | egrep "http\:\/\/|https\:\/\/" | cut -d\/ -f3 | sort -u | tee $LOOT_DIR/web/javascript-$TARGET-domains.txt
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING SECRETFINDER $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      if ! command -v secretfinder &> /dev/null; then
        echo -e "${OKRED}SecretFinder not found. Installing...${RESET}"
        git clone https://github.com/m4ll0k/SecretFinder.git $PLUGINS_DIR/SecretFinder
        pip3 install -r $PLUGINS_DIR/SecretFinder/requirements.txt
        # Attempt to run it via python if not in PATH
        if ! command -v secretfinder &> /dev/null; then
            PYTHON_SECRETFINDER_PATH="$PLUGINS_DIR/SecretFinder/SecretFinder.py"
        else
            PYTHON_SECRETFINDER_PATH="secretfinder" # It's in the PATH
        fi
      else
        PYTHON_SECRETFINDER_PATH="secretfinder" # It's in the PATH
      fi

      if [ -n "$PYTHON_SECRETFINDER_PATH" ]; then
        for file in $LOOT_DIR/web/javascript/$TARGET/*.js; do
          echo "Analyzing $file with SecretFinder"
          if [ "$PYTHON_SECRETFINDER_PATH" = "secretfinder" ]; then
            secretfinder -i $file -o cli >> $LOOT_DIR/web/javascript-$TARGET-secrets.txt
          else
            python3 $PYTHON_SECRETFINDER_PATH -i $file -o cli >> $LOOT_DIR/web/javascript-$TARGET-secrets.txt
          fi
        done
        echo "SecretFinder analysis complete. Results appended to $LOOT_DIR/web/javascript-$TARGET-secrets.txt"
      else
        echo -e "${OKRED}Failed to install or locate SecretFinder. Skipping SecretFinder analysis.${RESET}"
      fi

      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED CHECKING FOR CUSTOM JAVASCRIPT PATTERNS $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      
      PATTERN_FILE="/usr/share/sniper/conf/interesting_js_patterns.txt"
      CUSTOM_GREP_OUTPUT_FILE="$LOOT_DIR/web/javascript-$TARGET-custom_grep_findings.txt"

      if [[ ! -f "$PATTERN_FILE" ]]; then
        echo -e "$OKORANGE + -- --=[Custom JS pattern file not found: $PATTERN_FILE. Skipping this scan step.$RESET"
        echo -e "$OKORANGE + -- --=[To enable, create this file and add your grep ERE patterns, one per line.$RESET"
      else
        echo -e "$OKBLUE + -- --=[Scanning JavaScript files for custom patterns using $PATTERN_FILE...$RESET"
        
        found_any_custom_patterns=false
        # Note: CUSTOM_GREP_OUTPUT_FILE is created only if matches are found.

        for js_file_path in $LOOT_DIR/web/javascript/$TARGET/*.js; do
          if [[ -f "$js_file_path" ]]; then
            # Grep for patterns.
            # -E for extended regex, -n for line numbers, -H for filename, -i for case-insensitive.
            grep_output=$(grep -E -n -H -i -f "$PATTERN_FILE" "$js_file_path" 2>/dev/null)
            if [[ -n "$grep_output" ]]; then
              if ! $found_any_custom_patterns; then
                echo -e "$OKBLUE + -- --=[Custom patterns found. Results are being saved to $CUSTOM_GREP_OUTPUT_FILE$RESET"
                # Add a header to the output file only once when the first match is found.
                echo "Custom Grep Pattern Findings for Target: $TARGET" > "$CUSTOM_GREP_OUTPUT_FILE"
                echo "Patterns from: $PATTERN_FILE" >> "$CUSTOM_GREP_OUTPUT_FILE"
                echo "===========================================" >> "$CUSTOM_GREP_OUTPUT_FILE"
                found_any_custom_patterns=true
              fi
              # Append the grep output which already includes filename due to -H
              echo "$grep_output" >> "$CUSTOM_GREP_OUTPUT_FILE"
              echo "" >> "$CUSTOM_GREP_OUTPUT_FILE" # Add a newline for readability between file outputs
            fi
          fi
        done

        if $found_any_custom_patterns; then
          echo -e "$OKGREEN + -- --=[Custom JS pattern scanning complete. Results saved to: $CUSTOM_GREP_OUTPUT_FILE$RESET"
        else
          echo -e "$OKBLUE + -- --=[No custom JS patterns found in any files.$RESET"
          # If no patterns were found, the output file is not created.
          # To explicitly create an empty report, one could echo "No custom patterns found." > "$CUSTOM_GREP_OUTPUT_FILE" here.
          # For now, following the logic that file is only created on first match.
        fi
      fi
      WEB_JAVASCRIPT_ANALYSIS="0"
