pipeline {
    agent any
    
    options {
        timeout(time: 1, unit: 'HOURS')  // 빌드 타임아웃 설정
        disableConcurrentBuilds()  // 동시 빌드 방지
    }
    
    environment {
        SERVICE_NAME = 'admin-service'
        DOCKER_IMAGE_NAME = "${SERVICE_NAME}"
        AWS_ECR_REPO = "651706756261.dkr.ecr.ap-northeast-2.amazonaws.com/${SERVICE_NAME}"
        AWS_REGION = 'ap-northeast-2'
        DISCORD_WEBHOOK = credentials('jenkins-discord-webhook')
    }
    
    triggers {
        githubPush()
    }
    
    stages {
        stage('Checkout') {
            steps {
                cleanWs()
                checkout scm
            }
        }
        
        stage('Build Docker Image') {
            steps {
                script {
                    // 디버깅용 정보 출력
                    sh '''
                        pwd
                        ls -la
                        docker --version
                        aws --version
                    '''
                    
                    // AWS 인증
                    withCredentials([
                        string(credentialsId: 'aws-access-key-id', variable: 'AWS_ACCESS_KEY_ID'),
                        string(credentialsId: 'aws-secret-access-key', variable: 'AWS_SECRET_ACCESS_KEY')
                    ]) {
                        sh """
                            aws configure set aws_access_key_id ${AWS_ACCESS_KEY_ID}
                            aws configure set aws_secret_access_key ${AWS_SECRET_ACCESS_KEY}
                            aws configure set region ${AWS_REGION}
                            
                            # ECR 로그인
                            aws ecr get-login-password --region ${AWS_REGION} | docker login --username AWS --password-stdin ${AWS_ECR_REPO}
                        """
                    }
                    
                    // Docker 빌드 및 푸시
                    sh """
                        # 빌드
                        echo "Building Docker image..."
                        docker build -t ${DOCKER_IMAGE_NAME}:${BUILD_NUMBER} .
                        
                        # 태그 설정
                        echo "Tagging Docker image..."
                        docker tag ${DOCKER_IMAGE_NAME}:${BUILD_NUMBER} ${AWS_ECR_REPO}:${BUILD_NUMBER}
                        docker tag ${DOCKER_IMAGE_NAME}:${BUILD_NUMBER} ${AWS_ECR_REPO}:latest
                        
                        # ECR 푸시
                        echo "Pushing to ECR..."
                        docker push ${AWS_ECR_REPO}:${BUILD_NUMBER}
                        docker push ${AWS_ECR_REPO}:latest
                    """
                }
            }
        }
    }
    
    post {
        success {
            script {
                discordSend(
                    description: "[${SERVICE_NAME}] ✅ 빌드 성공 #${BUILD_NUMBER}\n브랜치: ${env.BRANCH_NAME}\n이미지 태그: ${BUILD_NUMBER}", 
                    title: "${SERVICE_NAME} 빌드 알림",
                    webhookURL: DISCORD_WEBHOOK,
                    footer: "Jenkins Pipeline"
                )
            }
        }
        failure {
            script {
                discordSend(
                    description: "[${SERVICE_NAME}] ❌ 빌드 실패 #${BUILD_NUMBER}\n브랜치: ${env.BRANCH_NAME}", 
                    title: "${SERVICE_NAME} 빌드 알림",
                    webhookURL: DISCORD_WEBHOOK,
                    footer: "Jenkins Pipeline"
                )
            }
        }
        always {
            script {
                // 로컬 Docker 이미지 정리
                sh """
                    docker rmi ${DOCKER_IMAGE_NAME}:${BUILD_NUMBER} || true
                    docker rmi ${AWS_ECR_REPO}:${BUILD_NUMBER} || true
                    docker rmi ${AWS_ECR_REPO}:latest || true
                """
            }
            cleanWs()
        }
    }
}