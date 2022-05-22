package app

import (
	"context"
	"sync"
)

type TcpDump interface {
	TcpDumpCapture(context.Context, *sync.WaitGroup)
	FixBrokenPackage(context.Context)
}
