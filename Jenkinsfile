pipeline {
    agent any

    options {
        buildDiscarder(logRotator(numToKeepStr: '10', artifactNumToKeepStr: '10'))
    }

    stages {
        stage('Trigger worsica CICD job') {
            when {
                anyOf {
                    branch 'master'
                    //branch 'development'
                }
            }
            steps {
                script {
                    build job: "/${JOB_NAME}".replace('worsica-frontend', 'worsica-cicd'),
                          propagate: true
                }
            }
        }
    }
}
