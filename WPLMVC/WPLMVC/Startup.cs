using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(WPLMVC.Startup))]
namespace WPLMVC
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
