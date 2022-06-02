package mock

import (
	"context"
	"sync"
)

type MockedTcpDump struct {
	MockTcpDumpCapture   func(context.Context, *sync.WaitGroup)
	MockFixBrokenPackage func(context.Context)
}

func (m *MockedTcpDump) TcpDumpCapture(ctx context.Context, wg *sync.WaitGroup) {
	if m.MockTcpDumpCapture != nil {
		m.MockTcpDumpCapture(ctx, wg)
	}
}

func (m *MockedTcpDump) FixBrokenPackage(ctx context.Context) {
	if m.MockFixBrokenPackage != nil {
		m.MockFixBrokenPackage(ctx)
	}
}
