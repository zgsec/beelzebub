package main

import (
	"flag"
	"os"
	"runtime/debug"

	"github.com/beelzebub-labs/beelzebub/v3/internal/builder"
	bzbparser "github.com/beelzebub-labs/beelzebub/v3/internal/parser"

	log "github.com/sirupsen/logrus"
)

func main() {
	var (
		quit                            = make(chan struct{})
		configurationsCorePath          string
		configurationsServicesDirectory string
		memLimitMiB                     int
		validateOnly                    bool
	)

	flag.StringVar(&configurationsCorePath, "confCore", "./configurations/beelzebub.yaml", "Provide the path of configurations core")
	flag.StringVar(&configurationsServicesDirectory, "confServices", "./configurations/services/", "Directory config services")
	flag.IntVar(&memLimitMiB, "memLimitMiB", 100, "Process Memory in MiB (default 100, set to -1 to use system default)")
	flag.BoolVar(&validateOnly, "validate", false, "Validate configuration files and exit (non-zero on errors)")
	flag.Parse()

	if memLimitMiB > 0 {
		// SetMemoryLimit takes an int64 value for the number of bytes.
		// bytes value = MiB value * 1024 * 1024
		debug.SetMemoryLimit(int64(memLimitMiB * 1024 * 1024))
	}

	cfgParser := bzbparser.Init(configurationsCorePath, configurationsServicesDirectory)

	coreConfigurations, err := cfgParser.ReadConfigurationsCore()
	failOnError(err, "Error during ReadConfigurationsCore: ")

	beelzebubServicesConfiguration, err := cfgParser.ReadConfigurationsServices()
	failOnError(err, "Error during ReadConfigurationsServices: ")

	// -validate: statically check configs (core + services, including the
	// per-protocol validators registered via init()) and exit. Non-zero exit
	// on any error-level finding. Registered validators are present because
	// the builder import above pulls in every protocol package.
	if validateOnly {
		coreResult := bzbparser.ValidateCore(coreConfigurations, configurationsCorePath)
		servicesResult := bzbparser.Validate(beelzebubServicesConfiguration, nil)
		coreResult.Print()
		servicesResult.Print()
		if coreResult.ExitCode() != 0 || servicesResult.ExitCode() != 0 {
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Load persona.yaml from the services directory (or PERSONA_DIR override).
	// Backward-compat: warn and continue with an empty persona if file is absent.
	personaDir := configurationsServicesDirectory
	if envDir := os.Getenv("PERSONA_DIR"); envDir != "" {
		personaDir = envDir
	}
	persona, personaErr := bzbparser.LoadPersona(personaDir)
	if personaErr != nil {
		log.Warnf("persona.yaml not found at %s: %v (running with empty persona)", personaDir, personaErr)
		persona = &bzbparser.Persona{}
	}

	beelzebubBuilder := builder.NewBuilder()
	beelzebubBuilder.SetPersona(persona)

	director := builder.NewDirector(beelzebubBuilder)

	beelzebubBuilder, err = director.BuildBeelzebub(coreConfigurations, beelzebubServicesConfiguration)
	failOnError(err, "Error during BuildBeelzebub: ")

	err = beelzebubBuilder.Run()
	failOnError(err, "Error during run beelzebub core: ")

	defer beelzebubBuilder.Close()

	<-quit
}

func failOnError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
	}
}
