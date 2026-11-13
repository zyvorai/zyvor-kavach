// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

// Typosquat-shape check. The embedded lists are deliberately small and are
// not a reputation database: a name that is one edit away from a popular name
// is only a low-severity hint. npm and pypi carry about 100 names each; the
// other ecosystems carry a shorter list (see docs/lockfile-inspection.md).

import "strings"

var lfPopular = map[string]map[string]bool{}

func init() {
	add := func(eco, names string) {
		m := map[string]bool{}
		for _, n := range strings.Fields(names) {
			m[n] = true
		}
		lfPopular[eco] = m
	}
	add("npm", `react react-dom lodash express axios chalk commander moment request async debug tslib typescript webpack babel-core eslint prettier jquery vue angular underscore bluebird uuid yargs glob minimist mkdirp rimraf semver colors inquirer dotenv body-parser cors mongoose mysql redis socket.io jest mocha chai sinon cheerio puppeteer next nuxt gulp grunt bootstrap rxjs core-js classnames prop-types redux react-redux react-router history immutable ramda date-fns dayjs validator joi yup nodemon ts-node winston morgan passport jsonwebtoken bcrypt bcryptjs multer helmet compression cookie-parser ejs pug handlebars marked highlight.js d3 three chart.js lodash-es node-fetch got superagent ws fs-extra execa ora shelljs cross-env concurrently husky lint-staged rollup vite esbuild postcss autoprefixer sass less`)
	add("pypi", `requests numpy pandas scipy matplotlib django flask urllib3 boto3 botocore setuptools pip wheel six pytest sqlalchemy pyyaml jinja2 cryptography certifi idna charset-normalizer click colorama attrs packaging pillow lxml beautifulsoup4 selenium scikit-learn tensorflow torch keras redis psycopg2 pymysql pymongo celery gunicorn uvicorn fastapi pydantic aiohttp httpx tornado twisted paramiko pycrypto simplejson ujson markupsafe werkzeug itsdangerous docutils sphinx nose mock tox virtualenv pylint flake8 black isort mypy coverage tqdm rich typer openpyxl xlrd xlwt python-dateutil pytz tzlocal docker kubernetes ansible fabric invoke pexpect psutil protobuf grpcio google-api-core awscli s3transfer jmespath cachetools oauthlib pyjwt bcrypt passlib decorator regex nltk spacy gensim seaborn plotly bokeh dash networkx sympy`)
	add("go", `github.com/gin-gonic/gin github.com/gorilla/mux github.com/stretchr/testify github.com/sirupsen/logrus github.com/spf13/cobra github.com/spf13/viper github.com/golang/protobuf github.com/pkg/errors github.com/google/uuid github.com/go-sql-driver/mysql github.com/lib/pq github.com/gorilla/websocket github.com/prometheus/client_golang github.com/aws/aws-sdk-go github.com/docker/docker github.com/labstack/echo github.com/urfave/cli github.com/fatih/color golang.org/x/crypto golang.org/x/net golang.org/x/sys golang.org/x/text google.golang.org/grpc google.golang.org/protobuf gopkg.in/yaml.v2 gopkg.in/yaml.v3 go.uber.org/zap`)
	add("cargo", `serde serde_json tokio rand clap regex lazy_static log env_logger futures hyper reqwest syn quote proc-macro2 libc bitflags chrono itertools once_cell anyhow thiserror rayon crossbeam bytes tracing url uuid base64 num_cpus smallvec parking_lot openssl mio`)
	add("gem", `rails rake rspec bundler nokogiri devise puma sinatra rack activesupport activerecord json minitest thor sidekiq redis pg mysql2 capybara faker factory_bot rubocop pry unicorn jwt bcrypt addressable faraday httparty`)
	add("composer", `symfony/console symfony/http-foundation laravel/framework guzzlehttp/guzzle monolog/monolog phpunit/phpunit doctrine/orm doctrine/dbal twig/twig psr/log league/flysystem nesbot/carbon ramsey/uuid vlucas/phpdotenv illuminate/support`)
	add("maven", `org.springframework:spring-core org.springframework:spring-web org.springframework.boot:spring-boot junit:junit org.slf4j:slf4j-api ch.qos.logback:logback-classic com.google.guava:guava org.apache.commons:commons-lang3 commons-io:commons-io com.fasterxml.jackson.core:jackson-databind com.google.code.gson:gson org.apache.logging.log4j:log4j-core org.apache.httpcomponents:httpclient org.mockito:mockito-core org.hibernate:hibernate-core mysql:mysql-connector-java org.projectlombok:lombok`)
	add("nuget", `newtonsoft.json serilog automapper dapper nunit xunit moq entityframework polly nlog castle.core restsharp log4net microsoft.extensions.logging`)
}

// lfED1 reports whether a and b differ by exactly one insertion, deletion,
// substitution or adjacent transposition.
func lfED1(a, b string) bool {
	if a == b {
		return false
	}
	la, lb := len(a), len(b)
	if la-lb > 1 || lb-la > 1 {
		return false
	}
	i := 0
	for i < la && i < lb && a[i] == b[i] {
		i++
	}
	switch {
	case la == lb:
		if a[i+1:] == b[i+1:] {
			return true
		}
		return i+1 < la && a[i] == b[i+1] && a[i+1] == b[i] && a[i+2:] == b[i+2:]
	case la > lb:
		return a[i+1:] == b[i:]
	default:
		return b[i+1:] == a[i:]
	}
}

// lfTyposquat returns the popular name a package name shadows.
func lfTyposquat(eco, name string) (string, bool) {
	pop := lfPopular[eco]
	if pop == nil {
		return "", false
	}
	n := strings.ToLower(name)
	if pop[n] || len(n) < 5 || strings.HasPrefix(n, "@") {
		return "", false
	}
	best := ""
	for p := range pop {
		if len(p) >= 5 && lfED1(n, p) && (best == "" || p < best) {
			best = p
		}
	}
	return best, best != ""
}
