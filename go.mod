module github.com/sylvester-francis/watchdog-agent

go 1.25.6

require (
	github.com/gorilla/websocket v1.5.3
	github.com/sylvester-francis/watchdog-proto v0.3.0
)

replace github.com/sylvester-francis/watchdog-proto => ../watchdog-proto
