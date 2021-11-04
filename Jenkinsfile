pipeline {

  parameters {
      string (
        name: 'repository_url',
        defaultValue: 'https://github.com/wesley-dean-flexion/aws_ssh_authentication_helper.git',
        description: 'the URL to the Git repository'
      )

    string (
        name: 'git_credential',
        defaultValue: 'github-wesley-dean',
        description: 'the ID of the credential to use to interact with GitHub'
      )
    }

    environment {
        repository_url = "$params.repository_url"
        git_credential = "$params.git_credential"
        build_time = sh(script: "date --rfc-3339=seconds", returnStdout: true).trim()
    }
      
    triggers {
        cron('@monthly')
    }

    options {
        timestamps()
        ansiColor('xterm')
    }

    agent any
    stages {
        stage ('Checkout') {
            steps {
                git branch: 'master',
                credentialsId: git_credential,
                url: repository_url
            }
        }

        stage ('Semgrep') {
            agent {
                docker {
                    image 'returntocorp/semgrep'
                    args '--entrypoint=""'
                }            
            }

            steps {
                sh 'semgrep --config auto --error "${WORKSPACE}"'
            }
        }

        stage ('Awesome CI') {
            agent {
                docker {
                    image 'cytopia/awesome-ci'
                    reuseNode true
                }
            }

            steps {
                script {
                    def tests = [
                        'file-trailing-space': '--text', 
                        'file-utf8':           '--text',
                        'syntax-bash':         '--extension=bash',
                        'syntax-markdown':     '--extension=md',
                        'syntax-perl':         '--extension=pl',
                        'syntax-php':          '--extension=php,phps',
                        'syntax-ruby':         '--extension=rb',
                        'syntax-sh':           '--extension=sh',
                    ]

                    tests.each() {
                        sh "$it.key $it.value --ignore='.git,.svn' --path='.'"
                    }
                }
            }
        }
    }
}
