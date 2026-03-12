using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.AspNetCore.Identity.UI.Services;
using MimeKit;

namespace AuthServer.Host.Services;

public class EmailSender : IEmailSender
{
    private readonly IConfiguration _configuration;
    private readonly ILogger<EmailSender> _logger;

    public EmailSender(IConfiguration configuration, ILogger<EmailSender> logger)
    {
        _configuration = configuration;
        _logger = logger;
    }

    public async Task SendEmailAsync(string email, string subject, string htmlMessage)
    {
        try
        {
            // Читаем настройки из конфигурации
            var host = _configuration["SMTP:HOST"];
            var portString = _configuration["SMTP:PORT"];
            var user = _configuration["SMTP:USER"];
            var password = _configuration["SMTP:PASSWORD"];
            var fromEmail = _configuration["SMTP:FROM"];
            var fromName = _configuration["SMTP:FROMNAME"] ?? "Shulgan Auth";

            if (string.IsNullOrEmpty(host) || string.IsNullOrEmpty(user) || string.IsNullOrEmpty(password))
            {
                _logger.LogWarning("Настройки SMTP не заданы. Письмо на {Email} не отправлено.", email);
                return;
            }

            int port = int.TryParse(portString, out var p) ? p : 587; // Порт Resend по умолчанию

            // Формируем письмо
            var message = new MimeMessage();
            message.From.Add(new MailboxAddress(fromName, fromEmail));
            message.To.Add(new MailboxAddress("", email));
            message.Subject = subject;

            // Identity отправляет письма в HTML формате
            var bodyBuilder = new BodyBuilder { HtmlBody = htmlMessage };
            message.Body = bodyBuilder.ToMessageBody();

            // Отправляем через MailKit
            using var client = new SmtpClient();

            // StartTls - стандарт для порта 587
            await client.ConnectAsync(host, port, SecureSocketOptions.StartTls);
            await client.AuthenticateAsync(user, password);

            await client.SendAsync(message);
            await client.DisconnectAsync(true);

            _logger.LogInformation("Письмо '{Subject}' успешно отправлено на {Email}", subject, email);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Ошибка при отправке письма на {Email}", email);
            throw; // Пробрасываем ошибку, чтобы UI знал, что отправка не удалась
        }
    }
}
