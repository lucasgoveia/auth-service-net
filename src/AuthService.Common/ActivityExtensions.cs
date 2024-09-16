using System.Diagnostics;
using System.Runtime.CompilerServices;
using OpenTelemetry.Trace;

namespace AuthService.Common;

public static class ActivityExtensions
{
    public static void WithActivity(this ActivitySource source, Action<Activity?> action, [CallerMemberName] string name = "")
    {
        using var activity = source.StartActivity(name);
        try
        {
            action(activity);
        }
        catch (Exception ex)
        {
            activity?.SetStatus(ActivityStatusCode.Error);
            activity?.RecordException(ex);
            throw;
        }
    }
    
    
    /// <summary>
    /// Método de extensão para facilitar o uso de activities
    /// </summary>
    /// <param name="source">Activity source da aplicação</param>
    /// <param name="func">Método a ser executado na activity</param>
    /// <param name="name">Nome da activity. É inferido pelo método que chama esta extensão</param>
    /// <typeparam name="T">Tipo do retorno</typeparam>
    /// <returns></returns>
    public static T WithActivity<T>(this ActivitySource source, Func<Activity?, T> func, [CallerMemberName] string name = "")
    {
        using var activity = source.StartActivity(name);
        try
        {
            return func(activity);
        }
        catch (Exception ex)
        {
            activity?.SetStatus(ActivityStatusCode.Error);
            activity?.RecordException(ex);
            throw;
        }
    }
    
    
    
    /// <summary>
    /// Método de extensão para facilitar o uso de activities
    /// </summary>
    /// <param name="source">Activity source da aplicação</param>
    /// <param name="func">Método a ser executado na activity</param>
    /// <param name="name">Nome da activity. É inferido pelo método que chama esta extensão</param>
    /// <returns></returns>
    public static async Task WithActivity(this ActivitySource source, Func<Activity?, Task> func, [CallerMemberName] string name = "")
    {
        using var activity = source.StartActivity(name);
        try
        {
            await func(activity);
        }
        catch (Exception ex)
        {
            activity?.SetStatus(ActivityStatusCode.Error);
            activity?.RecordException(ex);
            throw;
        }
    }
    
    
    /// <summary>
    /// Método de extensão para facilitar o uso de activities
    /// </summary>
    /// <param name="source">Activity source da aplicação</param>
    /// <param name="func">Método a ser executado na activity</param>
    /// <param name="name">Nome da activity. É inferido pelo método que chama esta extensão</param>
    /// <typeparam name="T">Tipo do retorno</typeparam>
    /// <returns></returns>
    public static async Task<T> WithActivity<T>(this ActivitySource source, Func<Activity?, Task<T>> func, [CallerMemberName] string name = "")
    {
        using var activity = source.StartActivity(name);
        try
        {
            return await func(activity);
        }
        catch (Exception ex)
        {
            activity?.SetStatus(ActivityStatusCode.Error);
            activity?.RecordException(ex);
            throw;
        }
    }
}