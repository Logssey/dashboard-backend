#!/usr/bin/env bash
# Builds the Spring-Boot-layout test jars (BOOT-INF/classes + BOOT-INF/lib) into $FIXTURE_BUILD:
#   app-like.jar       mirrors service-backend (Argon2 via Spring Security, @RequestBody DTOs, no container auth)
#   app-positive.jar   positive controls: every CVE condition deliberately present
#   app-tokens.jar     CVE-2026-89407 control: a BigDecimal type named only by a class literal passed to a generic helper
#   app-indirect.jar   the app-positive conditions one step removed (nesting, subclasses, JCE names, ObjectReader)
#   app-blindspots.jar reflection / runtime type names (known misses, pinned) and a mix-in (must not be over-reported)
#   app-generic.jar    request bodies typed by a type variable (CrudController<T>): the type each subtype gives is the DTO
#   app-boot2.jar      app-like on Spring Boot 2: the Tomcat rules were checked on Spring Boot 4 only, so they must not say unreachable
# Real bytecode: bcprov 1.78.1, jackson 2.16.1, commons-logging 1.3.0 (Gradle puts them in $FIXTURE_LIBS),
# spring-security-crypto 7.1.1 (compiled from the official sources). Spring MVC/Boot and Tomcat are stubs
# with the real class/method names and descriptors.
set -euo pipefail
cd "$(dirname "$0")"
# 기대값(expected.json)은 아래 버전의 jar 기준이다. ./gradlew :reach-analyzer:copyFixtureLibs가 FIXTURE_LIBS에 받아 둔다.
L="${FIXTURE_LIBS:-../build/fixture-libs}"
BC="$L/bcprov-jdk18on-1.78.1.jar"
JC="$L/jackson-core-2.16.1.jar"; JD="$L/jackson-databind-2.16.1.jar"; JA="$L/jackson-annotations-2.16.1.jar"
CL="$L/commons-logging-1.3.0.jar"
for f in "$BC" "$JC" "$JD" "$JA" "$CL"; do
  if [ ! -f "$f" ]; then
    echo "필요한 jar가 없다: $f"
    echo "./gradlew :reach-analyzer:copyFixtureLibs로 받거나 FIXTURE_LIBS=<jar 폴더>로 지정한다."
    exit 1
  fi
done
B="${FIXTURE_BUILD:-../build/fixtures}"
# B 자체는 지우지 않는다(run-tests.sh가 이 안에 로그를 쓰고 있다)
rm -rf "$B/c" "$B/lib" "$B/fat"; mkdir -p "$B/c" "$B/lib"
jc() { local out=$1; shift; local cp=$1; shift; mkdir -p "$B/c/$out"; javac --release 21 -nowarn -encoding UTF-8 -cp "$cp" -d "$B/c/$out" $(find "$@" -name '*.java') 2>&1 | grep -v "Picked up" || true; }
jc spring-stubs "." fixture-src/spring-stubs
jc tomcat-stubs "." fixture-src/tomcat-stubs
jc boot-tomcat-stub "$B/c/tomcat-stubs" fixture-src/boot-tomcat-stub
jc bctls-stub "." fixture-src/bctls-stub
jc ssc "$BC:$CL:$B/c/spring-stubs" fixture-src/spring-security-crypto
jar cf "$B"/lib/spring-web-stub-7.0.0.jar -C "$B"/c/spring-stubs .
jar cf "$B"/lib/tomcat-embed-core-11.0.24-stub.jar -C "$B"/c/tomcat-stubs .
jar cf "$B"/lib/spring-boot-tomcat-stub-4.0.0.jar -C "$B"/c/boot-tomcat-stub .
jar cf "$B"/lib/spring-security-crypto-7.1.1.jar -C "$B"/c/ssc .
# Spring Boot itself only matters by its jar name (fact jar.springBoot4), so an empty jar is enough
mkdir -p "$B/c/empty"
jar cf "$B"/lib/spring-boot-4.0.0-stub.jar -C "$B"/c/empty .
cp "$BC" "$JC" "$JD" "$JA" "$CL" "$B/lib/"
LIBS=$(ls "$B"/lib/*.jar | tr '\n' ':')
jc app-like "$LIBS" fixture-src/app-like
jc app-positive "$LIBS" fixture-src/app-positive
jc app-tokens "$LIBS" fixture-src/app-tokens
jc app-indirect "$LIBS" fixture-src/app-indirect
jc app-blindspots "$LIBS" fixture-src/app-blindspots
jc app-generic "$LIBS" fixture-src/app-generic
for app in app-like app-positive app-tokens app-indirect app-blindspots app-generic; do
  F="$B/fat/$app"; mkdir -p "$F/BOOT-INF/classes" "$F/BOOT-INF/lib"
  cp -r "$B/c/$app/." "$F/BOOT-INF/classes/"
  cp "$B"/lib/*.jar "$F/BOOT-INF/lib/"
  if [ $app = app-positive ]; then jar cf "$F/BOOT-INF/lib/bctls-jdk18on-1.78.1-stub.jar" -C "$B"/c/bctls-stub .; fi
  jar cf "$B/$app.jar" -C "$F" .
done
F="$B/fat/app-boot2"; rm -rf "$F"; cp -r "$B/fat/app-like" "$F"
rm "$F/BOOT-INF/lib/spring-boot-4.0.0-stub.jar"
jar cf "$F/BOOT-INF/lib/spring-boot-2.7.18-stub.jar" -C "$B"/c/empty .
jar cf "$B/app-boot2.jar" -C "$F" .
ls -la "$B"/*.jar
