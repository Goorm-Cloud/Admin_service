pipeline {
    agent any
    
    environment {
        SERVICE_NAME = 'zoochacha-admin'
        DOCKER_IMAGE_NAME = 'zoochacha-admin'
        ECR_REPOSITORY = '${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${DOCKER_IMAGE_NAME}'
        AWS_REGION = 'ap-northeast-2'
        DISCORD_WEBHOOK = credentials('discord-webhook')
        GIT_CREDENTIALS_ID = 'github-credentials'
    }
    
    stages {
        stage('Checkout') {
            steps {
                cleanWs()
                checkout scm
            }
        }
        
        stage('Check Dependencies') {
            steps {
                sh '''
                    docker --version
                    aws --version
                '''
            }
        }
        
        stage('Configure AWS') {
            steps {
                withAWS(credentials: 'aws-credentials', region: env.AWS_REGION) {
                    sh 'aws ecr get-login-password --region ${AWS_REGION} | docker login --username AWS --password-stdin ${ECR_REPOSITORY}'
                }
            }
        }
        
        stage('Get Secrets') {
            steps {
                withAWS(credentials: 'aws-credentials', region: env.AWS_REGION) {
                    script {
                        def secrets = sh(
                            script: """
                                aws secretsmanager get-secret-value \
                                    --secret-id zoochacha-admin-secrets \
                                    --query SecretString \
                                    --output text
                            """,
                            returnStdout: true
                        ).trim()
                        
                        def secretsMap = readJSON text: secrets
                        
                        // Set environment variables from secrets
                        env.DB_USERNAME = secretsMap.DB_USERNAME
                        env.DB_PASSWORD = secretsMap.DB_PASSWORD
                        env.DB_HOST = secretsMap.DB_HOST
                        env.DB_PORT = secretsMap.DB_PORT
                        env.DB_NAME = secretsMap.DB_NAME
                    }
                }
            }
        }
        
        stage('Build Docker Image') {
            steps {
                script {
                    def imageTag = "${env.BUILD_NUMBER}"
                    sh """
                        docker build -t ${DOCKER_IMAGE_NAME}:${imageTag} \
                            --build-arg DB_USERNAME=${env.DB_USERNAME} \
                            --build-arg DB_PASSWORD=${env.DB_PASSWORD} \
                            --build-arg DB_HOST=${env.DB_HOST} \
                            --build-arg DB_PORT=${env.DB_PORT} \
                            --build-arg DB_NAME=${env.DB_NAME} \
                            .
                        docker tag ${DOCKER_IMAGE_NAME}:${imageTag} ${ECR_REPOSITORY}:${imageTag}
                        docker tag ${DOCKER_IMAGE_NAME}:${imageTag} ${ECR_REPOSITORY}:latest
                    """
                }
            }
        }
        
        stage('Push to ECR') {
            steps {
                script {
                    def imageTag = "${env.BUILD_NUMBER}"
                    sh """
                        docker push ${ECR_REPOSITORY}:${imageTag}
                        docker push ${ECR_REPOSITORY}:latest
                    """
                }
            }
        }
    }
    
    post {
        always {
            script {
                def color
                def status
                if (currentBuild.currentResult == 'SUCCESS') {
                    color = '3066993'
                    status = 'SUCCESS'
                } else {
                    color = '15158332'
                    status = 'FAILED'
                }
                
                discordSend(
                    webhookURL: DISCORD_WEBHOOK,
                    title: "${env.JOB_NAME} #${env.BUILD_NUMBER}",
                    description: "Build ${status}\n\nBranch: ${env.BRANCH_NAME}\nCommit: ${env.GIT_COMMIT}",
                    result: currentBuild.currentResult,
                    link: env.BUILD_URL,
                    footer: "Jenkins Pipeline",
                    thumbnail: "https://jenkins.io/images/logos/jenkins/jenkins.png",
                    customFields: [[name: 'Status', value: status]],
                    enableArtifactsList: false,
                    showChangeset: true
                )
                
                // Clean up local Docker images
                sh """
                    docker rmi ${DOCKER_IMAGE_NAME}:${env.BUILD_NUMBER} || true
                    docker rmi ${ECR_REPOSITORY}:${env.BUILD_NUMBER} || true
                    docker rmi ${ECR_REPOSITORY}:latest || true
                """
                
                cleanWs()
            }
        }
    }
} 