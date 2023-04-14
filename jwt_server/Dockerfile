FROM adoptopenjdk/openjdk11
ARG JAR_FILE_PATH=build/libs/jwt_server.jar
COPY ${JAR_FILE_PATH} app.jar
COPY pinpoint-agent-2.2.2 pinpoint-agent-2.2.2
COPY run.sh run.sh

ENTRYPOINT ["./run.sh"]
