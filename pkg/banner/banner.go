package banner

import "fmt"

const (
	Cyan   = "\033[36m"
	White  = "\033[37m"
	Green  = "\033[32m"
	Red    = "\033[31m"
	Yellow = "\033[33m"
	Reset  = "\033[0m"
)

func Print() {
	ascii := `
    ______           _
   / ____/__  ____  (_)_____ _
  / /_  / _ \/ __ \/ / ___/ /
 / __/ /  __/ / / / / /  / /
/_/    \___/_/ /_/_/_/  /_/
`
	fmt.Printf("%s%s%s\n", Red, ascii, Reset)
	fmt.Printf("%sLEVIATHAN.AC // FENRIR%s\n", White, Reset)
	fmt.Printf("%sWordPress Recon // Auto Triage%s\n", Cyan, Reset)
	fmt.Printf("%s[*]%s Leviathan console // scoped operations only\n\n", Green, Reset)
}
