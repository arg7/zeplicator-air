#!/bin/bash

# Launch tmux with 3 vertical panels watching zep-air log files

# Enable mouse support
tmux set-option -g mouse on 2>/dev/null

# Calculate dimensions
TOTAL_LINES=$(tput lines)
PANEL_LINES=$(( (TOTAL_LINES - 3) / 3 ))
TAIL_LINES=$(( PANEL_LINES - 2 ))

# Kill existing tmux session if it exists
tmux kill-session -t zep-watch 2>/dev/null

# Create new session in detached mode
tmux new-session -d -s zep-watch -n logs -x 255 -y ${TOTAL_LINES}

# Split into 3 equal-height panes using -l (exact line height)
tmux split-window -v -t zep-watch:0.0 -l ${PANEL_LINES}
tmux split-window -v -t zep-watch:0.0 -l ${PANEL_LINES}

# Run watch tail in each pane
tmux send-keys -t zep-watch:0.0 "watch -n 1 'tail -n ${TAIL_LINES} /tmp/zep-server.log | cut -c1-\$(tput cols)'" Enter
tmux send-keys -t zep-watch:0.1 "watch -n 1 'tail -n ${TAIL_LINES} /tmp/zep-za-client-1.log | cut -c1-\$(tput cols)'" Enter
tmux send-keys -t zep-watch:0.2 "watch -n 1 'tail -n ${TAIL_LINES} /tmp/zep-za-client-2.log | cut -c1-\$(tput cols)'" Enter

# Attach to the session
tmux attach-session -t zep-watch
