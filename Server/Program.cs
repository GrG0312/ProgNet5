namespace Server
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            ServerController controller = new ServerController();
            await controller.Start();
        }
    }
}
