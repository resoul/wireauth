package wireauth

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"
)

const (
	cmdStage1 = 1
	cmdStage2 = 2

	stage1ClientPacketSize = 4 + 16
	stage1ServerRespSize   = 16 + 256
	stage2ClientPubKeySize = 65
	stage2ClientPacketMin  = 4 + 65
)

type Session struct {
	AESKey      []byte
	ServerNonce []byte
}

type Server struct {
	privateKey *rsa.PrivateKey
	timeout    time.Duration
}

type Option func(*Server)

func WithTimeout(d time.Duration) Option {
	return func(s *Server) { s.timeout = d }
}

func NewServer(privateKey *rsa.PrivateKey, opts ...Option) *Server {
	s := &Server{
		privateKey: privateKey,
		timeout:    10 * time.Second,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

type deadlineSetter interface {
	SetReadDeadline(t time.Time) error
}

func (s *Server) Perform(ctx context.Context, conn MessageReadWriter) (*Session, error) {
	if ds, ok := conn.(deadlineSetter); ok {
		if err := ds.SetReadDeadline(time.Now().Add(s.timeout)); err != nil {
			return nil, fmt.Errorf("wireauth: failed to set read deadline: %w", err)
		}
		defer func() {
			_ = ds.SetReadDeadline(time.Time{})
		}()
	}

	clientNonce, serverNonce, err := s.performStage1(conn)
	if err != nil {
		return nil, err
	}

	aesKey, err := s.performStage2(conn, clientNonce, serverNonce)
	if err != nil {
		return nil, err
	}

	return &Session{AESKey: aesKey, ServerNonce: serverNonce}, nil
}

func (s *Server) performStage1(conn MessageReadWriter) (clientNonce, serverNonce []byte, err error) {
	for {
		msgType, packet, readErr := conn.ReadMessage()
		if readErr != nil {
			return nil, nil, fmt.Errorf("%w: %v", ErrHandshakeReadFailed, readErr)
		}
		if msgType != BinaryMessageType || len(packet) < stage1ClientPacketSize {
			continue
		}
		commandID := binary.LittleEndian.Uint32(packet[0:4])
		if commandID != cmdStage1 {
			continue
		}

		clientNonce = packet[4:20]

		serverNonce = make([]byte, 16)
		if _, err := rand.Read(serverNonce); err != nil {
			return nil, nil, fmt.Errorf("wireauth: failed to generate server nonce: %w", err)
		}

		dataToSign := make([]byte, len(clientNonce)+len(serverNonce))
		copy(dataToSign[:len(clientNonce)], clientNonce)
		copy(dataToSign[len(clientNonce):], serverNonce)
		hashed := sha256.Sum256(dataToSign)

		signature, err := rsa.SignPKCS1v15(rand.Reader, s.privateKey, crypto.SHA256, hashed[:])
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %v", ErrSignatureFailed, err)
		}

		response := make([]byte, len(serverNonce)+len(signature))
		copy(response[:len(serverNonce)], serverNonce)
		copy(response[len(serverNonce):], signature)
		if err := conn.WriteMessage(BinaryMessageType, response); err != nil {
			return nil, nil, fmt.Errorf("%w: %v", ErrHandshakeWriteFailed, err)
		}
		return clientNonce, serverNonce, nil
	}
}

func (s *Server) performStage2(conn MessageReadWriter, clientNonce, serverNonce []byte) ([]byte, error) {
	for {
		msgType, packet, readErr := conn.ReadMessage()
		if readErr != nil {
			return nil, fmt.Errorf("%w: %v", ErrHandshakeReadFailed, readErr)
		}
		if msgType != BinaryMessageType || len(packet) < stage2ClientPacketMin {
			continue
		}
		commandID := binary.LittleEndian.Uint32(packet[0:4])
		if commandID != cmdStage2 {
			continue
		}

		clientPubBytes := packet[4 : 4+stage2ClientPubKeySize]

		curve := ecdh.P256()
		serverPrivKey, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("wireauth: failed to generate server ECDH key: %w", err)
		}

		clientPubKey, err := curve.NewPublicKey(clientPubBytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidClientPubKey, err)
		}

		sharedSecret, err := serverPrivKey.ECDH(clientPubKey)
		if err != nil {
			return nil, fmt.Errorf("wireauth: ECDH failed: %w", err)
		}

		hasher := sha256.New()
		hasher.Write(sharedSecret)
		hasher.Write(clientNonce)
		hasher.Write(serverNonce)
		aesKey := hasher.Sum(nil)

		serverPubBytes := serverPrivKey.PublicKey().Bytes()
		if err := conn.WriteMessage(BinaryMessageType, serverPubBytes); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrHandshakeWriteFailed, err)
		}
		return aesKey, nil
	}
}
