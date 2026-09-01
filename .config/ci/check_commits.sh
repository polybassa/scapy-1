#!/bin/bash

# SPDX-License-Identifier: GPL-2.0-only

# Check all commits in the PR have the "AI-Assisted" tag
# We copy Wireshark's contributing guide, thanks to them for the idea !
# This script is inspired by https://gitlab.com/wireshark/wireshark/-/blob/master/.gitlab-ci.yml

commits=$(git rev-list --no-merges --after="2026-01-00T00:00:00" --max-count=$((PR_FETCH_DEPTH - 1)) HEAD)
if [ -z "$commits" ]; then
    echo "No commit to check in PR. OK."
    exit 0
fi

missing=0
copilot_missing=0
for c in $commits; do
    if ! git log -1 --format=%B "$c" | grep -qi '^AI-Assisted:'; then
        mapfile -t author_data < <(git log -1 --format='%an%n%ae' "$c")
        author_name="${author_data[0]}"
        author_email="${author_data[1]}"
        is_copilot_commit=0
        if [[ "$author_name" == "copilot-swe-agent[bot]" ]]; then
            is_copilot_commit=1
        elif [[ "$author_email" =~ \+Copilot@users\.noreply\.github\.com$ ]]; then
            is_copilot_commit=1
        fi

        if [ $is_copilot_commit -eq 1 ]; then
            echo -e "REMINDER: Commit \033[0;33m$c\033[0m (Copilot bot) is missing the 'AI-Assisted: yes|no [tool(s)]' trailer."
            copilot_missing=1
            continue
        fi
        echo -e "ERROR: Commit \033[0;33m$c\033[0m is missing the 'AI-Assisted: yes|no [tool(s)]' trailer."
        missing=1
    else
        echo -e "OK: Commit \033[0;32m$c\033[0m is properly tagged."
    fi
done

if [ $missing -eq 1 ]; then
    echo
    echo -e "\033[0;31mPlease add the 'AI-Assisted' trailer to commit messages !\033[0m"
    echo "See the contribution guide at: https://github.com/secdev/scapy/blob/master/CONTRIBUTING.md"
    exit 1
else
    if [ $copilot_missing -eq 1 ]; then
        echo "AI-Assisted trailer missing only in Copilot bot commits (reminder-only)."
    else
        echo "All checked commits include the AI-Assisted trailer."
    fi
    exit 0
fi
