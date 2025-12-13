pipeline {
    agent any
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        stage('Run Threat Check') {
            steps {
                sh 'python3 threat_intel/threat_check.py'
            }
        }
    }
}
