/* Icinga 2 | (c) 2012 Icinga GmbH | GPLv2+ */

#ifndef TLSSTREAM_H
#define TLSSTREAM_H

#include "base/i2-base.hpp"
#include "base/shared.hpp"
#include "base/socket.hpp"
#include "base/stream.hpp"
#include "base/tlsutility.hpp"
#include "base/fifo.hpp"
#include "base/utility.hpp"
#include <atomic>
#include <memory>
#include <utility>
#include <boost/asio/buffered_stream.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/ssl.hpp>

namespace icinga
{

template<class ARS>
class SeenStream : public ARS
{
public:
	template<class... Args>
	SeenStream(Args&&... args) : ARS(std::forward<Args>(args)...)
	{
		m_Seen.store(nullptr);
	}

	template<class... Args>
	auto async_read_some(Args&&... args) -> decltype(((ARS*)nullptr)->async_read_some(std::forward<Args>(args)...))
	{
		{
			auto seen (m_Seen.load());

			if (seen) {
				*seen = Utility::GetTime();
			}
		}

		return ((ARS*)this)->async_read_some(std::forward<Args>(args)...);
	}

	inline void SetSeen(double* seen)
	{
		m_Seen.store(seen);
	}

private:
	std::atomic<double*> m_Seen;
};

struct UnbufferedAsioTlsStreamParams
{
	boost::asio::io_context& IoContext;
	boost::asio::ssl::context& SslContext;
	const String& Hostname;
};

typedef SeenStream<boost::beast::ssl_stream<boost::beast::tcp_stream>> AsioTcpTlsStream;

class UnbufferedAsioTlsStream : public AsioTcpTlsStream
{
public:
	typedef typename next_layer_type::socket_type lowest_layer_type;

	inline
	UnbufferedAsioTlsStream(UnbufferedAsioTlsStreamParams& init)
		: AsioTcpTlsStream(init.IoContext, init.SslContext), m_VerifyOK(true), m_Hostname(init.Hostname)
	{
	}

	bool IsVerifyOK() const;
	String GetVerifyError() const;
	std::shared_ptr<X509> GetPeerCertificate();

	template<class... Args>
	inline
	auto async_handshake(handshake_type type, Args&&... args) -> decltype(((AsioTcpTlsStream*)nullptr)->async_handshake(type, std::forward<Args>(args)...))
	{
		BeforeHandshake(type);

		return AsioTcpTlsStream::async_handshake(type, std::forward<Args>(args)...);
	}

	template<class... Args>
	inline
	auto handshake(handshake_type type, Args&&... args) -> decltype(((AsioTcpTlsStream*)nullptr)->handshake(type, std::forward<Args>(args)...))
	{
		BeforeHandshake(type);

		return AsioTcpTlsStream::handshake(type, std::forward<Args>(args)...);
	}

	/// Get a reference to the lowest layer.
	/**
	 * This function returns a reference to the lowest layer in a stack of
	 * stream layers.
	 *
	 * @return A reference to the lowest layer in the stack of stream layers.
	 * Ownership is not transferred to the caller.
	 */
	lowest_layer_type& lowest_layer()
	{
		return next_layer().socket();
	}

	/// Get a reference to the lowest layer.
	/**
	 * This function returns a reference to the lowest layer in a stack of
	 * stream layers.
	 *
	 * @return A reference to the lowest layer in the stack of stream layers.
	 * Ownership is not transferred to the caller.
	 */
	const lowest_layer_type& lowest_layer() const
	{
		return next_layer().socket();
	}

private:
	bool m_VerifyOK;
	String m_VerifyError;
	String m_Hostname;

	void BeforeHandshake(handshake_type type);
};

class AsioTlsStream : public boost::asio::buffered_stream<UnbufferedAsioTlsStream>
{
public:
	inline
	AsioTlsStream(boost::asio::io_context& ioContext, boost::asio::ssl::context& sslContext, const String& hostname = String())
		: AsioTlsStream(UnbufferedAsioTlsStreamParams{ioContext, sslContext, hostname})
	{
	}

private:
	inline
	AsioTlsStream(UnbufferedAsioTlsStreamParams init)
		: buffered_stream(init)
	{
	}
};

typedef boost::asio::buffered_stream<boost::asio::ip::tcp::socket> AsioTcpStream;
typedef std::pair<Shared<AsioTlsStream>::Ptr, Shared<AsioTcpStream>::Ptr> OptionalTlsStream;

}

#endif /* TLSSTREAM_H */
