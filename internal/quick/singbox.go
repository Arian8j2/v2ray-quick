package quick

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxservice "github.com/sagernet/sing-box/adapter/service"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/tun"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing/common/json/badoption"

	"v2ray-quick/internal/link"
)

func BuildOptions(vless *link.VLESS, interfaceName string, tunAddress string) (option.Options, error) {
	outbound, err := buildVLESSOutbound(vless)
	if err != nil {
		return option.Options{}, err
	}
	address, err := netip.ParsePrefix(tunAddress)
	if err != nil {
		return option.Options{}, fmt.Errorf("invalid tun address %q: %w", tunAddress, err)
	}

	return option.Options{
		Log: &option.LogOptions{
			Level:     "info",
			Timestamp: true,
		},
		Inbounds: []option.Inbound{
			{
				Type: C.TypeTun,
				Tag:  "tun-in",
				Options: &option.TunInboundOptions{
					InterfaceName: interfaceName,
					Address:       badoption.Listable[netip.Prefix]{address},
					AutoRoute:     false,
				},
			},
		},
		Outbounds: []option.Outbound{
			outbound,
			{
				Type:    C.TypeDirect,
				Tag:     "direct",
				Options: &option.DirectOutboundOptions{},
			},
		},
		Route: &option.RouteOptions{
			Final:               "proxy",
			AutoDetectInterface: true,
		},
	}, nil
}

func buildVLESSOutbound(vless *link.VLESS) (option.Outbound, error) {
	if !strings.EqualFold(vless.Encryption, "none") {
		return option.Outbound{}, fmt.Errorf("unsupported vless encryption %q", vless.Encryption)
	}

	options := option.VLESSOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     vless.Server,
			ServerPort: vless.Port,
		},
		UUID: vless.UUID,
	}

	switch strings.ToLower(vless.Security.Type) {
	case "", "none":
	case "tls":
		options.TLS = &option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: vless.Security.ServerName,
			Insecure:   vless.Security.Insecure,
		}
	default:
		return option.Outbound{}, fmt.Errorf("unsupported vless security %q", vless.Security.Type)
	}

	switch strings.ToLower(vless.Transport.Type) {
	case "", "tcp":
	case "ws":
		headers := badoption.HTTPHeader{}
		if vless.Transport.Host != "" {
			headers["Host"] = badoption.Listable[string]{vless.Transport.Host}
		}
		options.Transport = &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeWebsocket,
			WebsocketOptions: option.V2RayWebsocketOptions{
				Path:    vless.Transport.Path,
				Headers: headers,
			},
		}
	default:
		return option.Outbound{}, fmt.Errorf("unsupported vless transport %q", vless.Transport.Type)
	}

	return option.Outbound{
		Type:    C.TypeVLESS,
		Tag:     "proxy",
		Options: &options,
	}, nil
}

func startSingBox(ctx context.Context, options option.Options) (*box.Box, context.CancelFunc, error) {
	ctx = singBoxContext(ctx)
	ctx, cancel := context.WithCancel(ctx)

	instance, err := box.New(box.Options{
		Context: ctx,
		Options: options,
	})
	if err != nil {
		cancel()
		return nil, nil, fmt.Errorf("create sing-box service: %w", err)
	}

	if err := instance.Start(); err != nil {
		cancel()
		return nil, nil, fmt.Errorf("start sing-box service: %w", err)
	}

	return instance, cancel, nil
}

func closeSingBox(instance *box.Box) error {
	closeCtx, closeCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer closeCancel()

	done := make(chan error, 1)
	go func() {
		done <- instance.Close()
	}()

	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("close sing-box service: %w", err)
		}
		return nil
	case <-closeCtx.Done():
		return errors.New("timed out closing sing-box service")
	}
}

func singBoxContext(ctx context.Context) context.Context {
	inboundRegistry := inbound.NewRegistry()
	tun.RegisterInbound(inboundRegistry)

	outboundRegistry := outbound.NewRegistry()
	direct.RegisterOutbound(outboundRegistry)
	vless.RegisterOutbound(outboundRegistry)

	dnsTransportRegistry := dns.NewTransportRegistry()
	local.RegisterTransport(dnsTransportRegistry)

	return box.Context(
		ctx,
		inboundRegistry,
		outboundRegistry,
		endpoint.NewRegistry(),
		dnsTransportRegistry,
		boxservice.NewRegistry(),
	)
}
