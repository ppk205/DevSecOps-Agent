FROM maven:3.9.9-eclipse-temurin-17@sha256:f58d59b6273e785ac0a4477f6e9b5ba1d7731c75b906c0f7b34076f1851318cc
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-venv unzip curl && rm -rf /var/lib/apt/lists/*
RUN python3 -m venv /opt/agent
ENV PATH="/opt/agent/bin:/opt/spotbugs/bin:/opt/dependency-check/bin:${PATH}" HOME=/tmp
WORKDIR /opt/source
COPY requirements-build.lock ./
RUN pip install --require-hashes -r requirements-build.lock
RUN curl -fLsS https://github.com/spotbugs/spotbugs/releases/download/4.10.4/spotbugs-4.10.4.tgz | tar xz -C /opt && mv /opt/spotbugs-4.10.4 /opt/spotbugs && chmod +x /opt/spotbugs/bin/*
RUN curl -fLsS https://repo.maven.apache.org/maven2/com/h3xstream/findsecbugs/findsecbugs-plugin/1.14.0/findsecbugs-plugin-1.14.0.jar -o /opt/findsecbugs.jar
RUN curl -fLsS https://github.com/dependency-check/DependencyCheck/releases/download/v13.0.0/dependency-check-13.0.0-release.zip -o /tmp/dc.zip && unzip /tmp/dc.zip -d /opt && rm /tmp/dc.zip && chmod +x /opt/dependency-check/bin/dependency-check.sh && ln -s /opt/dependency-check/bin/dependency-check.sh /usr/local/bin/dependency-check
COPY pyproject.toml README.md ./
COPY src ./src
COPY ci/smoke_installed.py ./ci/smoke_installed.py
RUN pip install --no-build-isolation --no-deps .
RUN python -I ci/smoke_installed.py
ENV MAVEN_CONFIG=/tmp/.m2
ENTRYPOINT []
WORKDIR /tmp
