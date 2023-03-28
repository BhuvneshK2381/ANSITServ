using System.Threading.Tasks;

namespace PlanningToolSSOServer.Services
{
    public interface ISmsSender
    {
        Task SendSmsAsync(string number, string message);
    }
}
