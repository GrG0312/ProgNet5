namespace Client
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            ClientController controller = new ClientController();
            await controller.Start();
        }
    }
}
