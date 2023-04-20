#!/bin/sh

java -Xms1024m -Xmx2048m -jar -javaagent:pinpoint-agent-2.2.2/pinpoint-bootstrap.jar app.jar
