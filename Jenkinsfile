pipeline {
    agent any

    tools {
        jdk 'JDK'
        nodejs 'node'
    }

    environment {
        SCANNER_HOME = tool 'sonarqube'
        IMAGE_NAME = 'enygmas/python-system-monitoring'
        TAG = "${env.BRANCH_NAME}-${env.BUILD_NUMBER}"
        REGISTRY_URL = 'https://index.docker.io/v1/'
    }

    stages {
        stage('Clean Workspace') {
            steps {
                cleanWs()
            }
        }

        stage('Checkout From Git') {
            steps {
                checkout scmGit(branches: [[name: '*/main']], extensions: [], userRemoteConfigs: [[credentialsId: 'github', url: 'https://github.com/Hardi5/Python-System-Monitoring.git']])
            }
        }

        stage('Docker Security Bench') {
            steps {
                script {
                    sh 'git clone https://github.com/docker/docker-bench-security.git || true' // Handle already existing directory
                    dir('docker-bench-security') { // Change directory context to 'docker-bench-security'
                        def output = sh(script: './docker-bench-security.sh', returnStdout: true)
                        output = output.replaceAll("\\x1B\\[[;\\d]*m", "") // Remove ANSI color codes
                        def warnLines = output.tokenize('\n').findAll { it.contains('[WARN]') }
                        warnLines.each {
                            println it.replaceAll("\\[Pipeline] echo", "").trim() // Print each warning line, remove extra tags
                        }
                    }
                    sh 'rm -rf docker-bench-security' // Cleanup
                }
            }
        }

        stage('SonarQube Analysis') {
            steps {
                withSonarQubeEnv('sonarqube') {
                    script {
                        def sonarScanner = tool name: 'sonarqube', type: 'hudson.plugins.sonar.SonarRunnerInstallation'
                        sh "${sonarScanner}/bin/sonar-scanner " +
                        "-Dsonar.projectKey=Python-Webapp " +
                        "-Dsonar.projectName=Python-Webapp " +
                        "-Dsonar.projectVersion=1.0 " +
                        "-Dsonar.sources=src,build " +
                        "-Dsonar.sourceEncoding=UTF-8 " +
                        "-Dsonar.python.version=3 "
                    }
                }
            }
        }

        stage('TRIVY File Scan') {
            steps {
                script {
                    def trivyFsOutput = sh(returnStdout: true, script: "trivy fs --scanners vuln,secret,misconfig --severity HIGH,CRITICAL .")
                    echo "TRIVY File Scan Output:\n${trivyFsOutput}"
                    if (trivyFsOutput.contains('CRITICAL') || trivyFsOutput.contains('HIGH')) {
                        error("High or critical vulnerabilities found. Failing build.")
                    } else {
                        echo "No high or critical vulnerabilities found."
                    }
                }
            }
        }

        stage('dp-check') {
            steps {
                dependencyCheck additionalArguments: '--scan ./src/ ./build/ --format XML', odcInstallation: 'dp-check'
                dependencyCheckPublisher pattern: '**/dependency-check-report.xml'
            }     
        }

        stage('Docker Scout FS') {
            steps {
                script {
                    withDockerRegistry(url: env.REGISTRY_URL, credentialsId: 'docker') {
                        sh 'docker-scout quickview fs://.'
                        sh 'docker-scout cves fs://.'
                    }
                }
            }
        }

        stage('Docker Build & Tag') {
            steps {
                withDockerRegistry(url: env.REGISTRY_URL, credentialsId: 'docker') {
                    sh "docker build -t ${IMAGE_NAME}:latest -f build/Dockerfile ."
                }
            }
        }

        stage('TRIVY Image Scan') {
            steps {
                script {
                    def trivyImageOutput = sh(returnStdout: true, script: "trivy image --ignore-unfixed --severity CRITICAL,HIGH ${IMAGE_NAME}:latest")
                    echo "TRIVY Image Scan Critical and High Vulnerabilities with Fixes:\n${trivyImageOutput}"
                }
            }
        }

        stage('Docker Push') {
            steps {
                withDockerRegistry(url: env.REGISTRY_URL, credentialsId: 'docker') {
                    sh "docker push ${IMAGE_NAME}:latest"
                }
            }
        }

        stage('Docker Scout Image') {
            steps {
                script {
                    withDockerRegistry(url: env.REGISTRY_URL, credentialsId: 'docker') {
                        sh 'docker-scout quickview ${IMAGE_NAME}:latest'
                        sh 'docker-scout cves --only-fixed ${IMAGE_NAME}:latest'
                        sh 'docker-scout recommendations ${IMAGE_NAME}:latest'
                    }
                }
            }
        }

        stage('Deploy to Container') {
            steps {
                sh 'docker ps -a | grep -q python1 && docker stop python1 && docker rm python1 || true'
                sh "docker run -d --name python1 -p 5000:5000 ${IMAGE_NAME}:latest"
            }
        }
    }
}
