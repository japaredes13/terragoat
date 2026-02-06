pipeline {
  agent any

  environment {
    JENKINS_CONTAINER = "jenkins-blueocean"
    TERRASCAN_IMAGE  = "tenable/terrascan:latest"
    TARGET_DIR       = "terraform/aws"
  }

  stages {
    stage('Checkout') {
      steps { checkout scm }
    }

    stage('Verificar path') {
      steps {
        sh '''
          set -eu
          echo "WORKSPACE=$WORKSPACE"
          ls -la terraform || true
          test -d terraform/aws
          ls -la terraform/aws | head -n 50
        '''
      }
    }

    stage('Terrascan (JSON + JUnit)') {
      steps {
        sh '''
          set -eu
          mkdir -p results

          docker run --rm \
            --volumes-from jenkins-blueocean \
            -w "$WORKSPACE" \
            tenable/terrascan:latest scan -i terraform -d terraform/aws \
            --output json > results/terrascan.json || true

          docker run --rm \
            --volumes-from jenkins-blueocean \
            -w "$WORKSPACE" \
            tenable/terrascan:latest scan -i terraform -d terraform/aws \
            --output junit-xml > results/terrascan.junit.xml || true

          test -s results/terrascan.json
          test -s results/terrascan.junit.xml
        '''
      }
    }

    stage('Mostrar findings (sin python, solo grep)') {
      steps {
        sh '''
          set -eu
          echo "=== resumen findings (rule_id, severity, file, line) ==="
          # Terrascan JSON suele contener estos campos; esto te imprime lo importante sin parsear JSON
          grep -E '"rule_id"|"severity"|"file"|"line"' -n results/terrascan.json | head -n 200 || true

          echo "=== resumen summary ==="
          grep -E '"policies_validated"|"violated_policies"|"high"|"medium"|"low"' -n results/terrascan.json | head -n 50 || true
        '''
      }
    }
  }

  post {
    always {
      archiveArtifacts artifacts: 'results/*', fingerprint: true
      junit testResults: 'results/terrascan.junit.xml', allowEmptyResults: true
    }
  }
}
