// Independent interoperability peer, never linked into the Rust kernel.
package main

import (
    "context"
    "fmt"
    "io"
    "net"
    "os"
    mux "github.com/sagernet/sing-mux"
    "github.com/sagernet/sing/common/buf"
    "github.com/sagernet/sing/common/logger"
    M "github.com/sagernet/sing/common/metadata"
    N "github.com/sagernet/sing/common/network"
)

type echo struct{}
func (echo) NewConnectionEx(_ context.Context, conn net.Conn, _, _ M.Socksaddr, _ N.CloseHandlerFunc) {
    defer conn.Close()
    io.Copy(conn, conn)
}
func (echo) NewPacketConnectionEx(_ context.Context, conn N.PacketConn, _, _ M.Socksaddr, _ N.CloseHandlerFunc) {
    defer conn.Close()
    for {
        packet := buf.NewPacket()
        packet.Resize(64, 0)
        target, err := conn.ReadPacket(packet)
        if err != nil {packet.Release();return}
        if err = conn.WritePacket(packet, target); err != nil {return}
    }
}
func main() {
    service, err := mux.NewService(mux.ServiceOptions{
        NewStreamContext: func(ctx context.Context, _ net.Conn) context.Context {return ctx},
        Logger: logger.NOP(), HandlerEx: echo{},
    })
    if err != nil {panic(err)}
    listener, err := net.Listen("tcp", "127.0.0.1:0")
    if err != nil {panic(err)}
    fmt.Println(listener.Addr().(*net.TCPAddr).Port)
    for {
        conn, err := listener.Accept()
        if err != nil {panic(err)}
        go func() {
            defer conn.Close()
            if err := service.NewConnection(context.Background(), conn, M.Metadata{}); err != nil {fmt.Fprintln(os.Stderr, err)}
        }()
    }
}
