FROM openjdk:17-jdk

COPY build/libs/api-gateway.jar api-gateway.jar

CMD [ "java", "-jar", "api-gateway.jar"]